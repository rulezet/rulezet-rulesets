rule TTP_XOR_WriteProcessMemory_3c46 {
  strings:
    $key_3c46 = { 6b 34 [2] 59 16 [2] 5f 23 [2] 71 23 [2] 4e 3f }

  condition:
    any of them
}