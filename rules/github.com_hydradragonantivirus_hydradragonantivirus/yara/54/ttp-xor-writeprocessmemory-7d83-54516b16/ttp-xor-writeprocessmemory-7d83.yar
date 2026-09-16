rule TTP_XOR_WriteProcessMemory_7d83 {
  strings:
    $key_7d83 = { 2a f1 [2] 18 d3 [2] 1e e6 [2] 30 e6 [2] 0f fa }

  condition:
    any of them
}