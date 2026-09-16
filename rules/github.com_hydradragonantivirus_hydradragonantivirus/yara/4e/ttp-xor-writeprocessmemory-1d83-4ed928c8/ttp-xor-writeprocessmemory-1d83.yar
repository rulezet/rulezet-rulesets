rule TTP_XOR_WriteProcessMemory_1d83 {
  strings:
    $key_1d83 = { 4a f1 [2] 78 d3 [2] 7e e6 [2] 50 e6 [2] 6f fa }

  condition:
    any of them
}