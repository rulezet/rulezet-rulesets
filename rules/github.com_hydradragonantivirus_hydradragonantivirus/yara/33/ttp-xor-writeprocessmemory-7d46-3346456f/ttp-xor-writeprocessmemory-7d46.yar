rule TTP_XOR_WriteProcessMemory_7d46 {
  strings:
    $key_7d46 = { 2a 34 [2] 18 16 [2] 1e 23 [2] 30 23 [2] 0f 3f }

  condition:
    any of them
}