rule TTP_XOR_WriteProcessMemory_6dd4 {
  strings:
    $key_6dd4 = { 3a a6 [2] 08 84 [2] 0e b1 [2] 20 b1 [2] 1f ad }

  condition:
    any of them
}