rule TTP_XOR_WriteProcessMemory_3a00 {
  strings:
    $key_3a00 = { 6d 72 [2] 5f 50 [2] 59 65 [2] 77 65 [2] 48 79 }

  condition:
    any of them
}