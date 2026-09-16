rule TTP_XOR_WriteProcessMemory_7b8b {
  strings:
    $key_7b8b = { 2c f9 [2] 1e db [2] 18 ee [2] 36 ee [2] 09 f2 }

  condition:
    any of them
}