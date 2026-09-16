rule TTP_XOR_WriteProcessMemory_18e6 {
  strings:
    $key_18e6 = { 4f 94 [2] 7d b6 [2] 7b 83 [2] 55 83 [2] 6a 9f }

  condition:
    any of them
}