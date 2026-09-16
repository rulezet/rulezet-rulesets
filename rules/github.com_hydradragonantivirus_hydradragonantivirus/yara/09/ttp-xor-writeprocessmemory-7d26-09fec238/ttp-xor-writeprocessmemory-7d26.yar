rule TTP_XOR_WriteProcessMemory_7d26 {
  strings:
    $key_7d26 = { 2a 54 [2] 18 76 [2] 1e 43 [2] 30 43 [2] 0f 5f }

  condition:
    any of them
}