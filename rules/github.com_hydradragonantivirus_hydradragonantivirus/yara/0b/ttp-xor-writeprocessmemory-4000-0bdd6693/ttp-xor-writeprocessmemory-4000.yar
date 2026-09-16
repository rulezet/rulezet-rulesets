rule TTP_XOR_WriteProcessMemory_4000 {
  strings:
    $key_4000 = { 17 72 [2] 25 50 [2] 23 65 [2] 0d 65 [2] 32 79 }

  condition:
    any of them
}