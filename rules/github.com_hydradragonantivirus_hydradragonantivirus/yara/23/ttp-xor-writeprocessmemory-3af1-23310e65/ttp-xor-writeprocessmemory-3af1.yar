rule TTP_XOR_WriteProcessMemory_3af1 {
  strings:
    $key_3af1 = { 6d 83 [2] 5f a1 [2] 59 94 [2] 77 94 [2] 48 88 }

  condition:
    any of them
}