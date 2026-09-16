rule TTP_XOR_WriteProcessMemory_7d32 {
  strings:
    $key_7d32 = { 2a 40 [2] 18 62 [2] 1e 57 [2] 30 57 [2] 0f 4b }

  condition:
    any of them
}