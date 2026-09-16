rule TTP_XOR_WriteProcessMemory_7d82 {
  strings:
    $key_7d82 = { 2a f0 [2] 18 d2 [2] 1e e7 [2] 30 e7 [2] 0f fb }

  condition:
    any of them
}