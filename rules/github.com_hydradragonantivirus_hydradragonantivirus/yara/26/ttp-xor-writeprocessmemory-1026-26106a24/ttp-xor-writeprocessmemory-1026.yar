rule TTP_XOR_WriteProcessMemory_1026 {
  strings:
    $key_1026 = { 47 54 [2] 75 76 [2] 73 43 [2] 5d 43 [2] 62 5f }

  condition:
    any of them
}