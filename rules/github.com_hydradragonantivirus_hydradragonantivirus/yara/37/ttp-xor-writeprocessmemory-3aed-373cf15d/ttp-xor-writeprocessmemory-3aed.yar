rule TTP_XOR_WriteProcessMemory_3aed {
  strings:
    $key_3aed = { 6d 9f [2] 5f bd [2] 59 88 [2] 77 88 [2] 48 94 }

  condition:
    any of them
}