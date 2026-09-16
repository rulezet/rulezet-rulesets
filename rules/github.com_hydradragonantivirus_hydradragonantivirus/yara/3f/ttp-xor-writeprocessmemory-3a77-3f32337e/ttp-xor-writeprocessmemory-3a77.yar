rule TTP_XOR_WriteProcessMemory_3a77 {
  strings:
    $key_3a77 = { 6d 05 [2] 5f 27 [2] 59 12 [2] 77 12 [2] 48 0e }

  condition:
    any of them
}