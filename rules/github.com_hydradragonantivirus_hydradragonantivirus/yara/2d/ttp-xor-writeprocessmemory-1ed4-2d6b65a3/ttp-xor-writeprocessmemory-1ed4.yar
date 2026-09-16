rule TTP_XOR_WriteProcessMemory_1ed4 {
  strings:
    $key_1ed4 = { 49 a6 [2] 7b 84 [2] 7d b1 [2] 53 b1 [2] 6c ad }

  condition:
    any of them
}