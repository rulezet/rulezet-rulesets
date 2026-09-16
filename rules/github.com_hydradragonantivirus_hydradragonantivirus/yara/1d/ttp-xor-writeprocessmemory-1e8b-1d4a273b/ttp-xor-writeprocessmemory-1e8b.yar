rule TTP_XOR_WriteProcessMemory_1e8b {
  strings:
    $key_1e8b = { 49 f9 [2] 7b db [2] 7d ee [2] 53 ee [2] 6c f2 }

  condition:
    any of them
}