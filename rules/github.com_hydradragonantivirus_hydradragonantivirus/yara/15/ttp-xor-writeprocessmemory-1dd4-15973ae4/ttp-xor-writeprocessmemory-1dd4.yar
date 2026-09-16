rule TTP_XOR_WriteProcessMemory_1dd4 {
  strings:
    $key_1dd4 = { 4a a6 [2] 78 84 [2] 7e b1 [2] 50 b1 [2] 6f ad }

  condition:
    any of them
}