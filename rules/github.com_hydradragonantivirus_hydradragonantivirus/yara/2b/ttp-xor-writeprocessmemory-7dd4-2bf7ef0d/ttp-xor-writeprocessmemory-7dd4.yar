rule TTP_XOR_WriteProcessMemory_7dd4 {
  strings:
    $key_7dd4 = { 2a a6 [2] 18 84 [2] 1e b1 [2] 30 b1 [2] 0f ad }

  condition:
    any of them
}