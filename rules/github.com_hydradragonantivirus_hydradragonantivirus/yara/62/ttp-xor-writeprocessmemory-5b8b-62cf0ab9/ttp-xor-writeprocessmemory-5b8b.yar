rule TTP_XOR_WriteProcessMemory_5b8b {
  strings:
    $key_5b8b = { 0c f9 [2] 3e db [2] 38 ee [2] 16 ee [2] 29 f2 }

  condition:
    any of them
}