rule TTP_XOR_WriteProcessMemory_5ed4 {
  strings:
    $key_5ed4 = { 09 a6 [2] 3b 84 [2] 3d b1 [2] 13 b1 [2] 2c ad }

  condition:
    any of them
}