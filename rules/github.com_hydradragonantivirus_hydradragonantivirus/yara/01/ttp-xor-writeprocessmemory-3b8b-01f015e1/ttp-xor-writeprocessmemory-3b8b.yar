rule TTP_XOR_WriteProcessMemory_3b8b {
  strings:
    $key_3b8b = { 6c f9 [2] 5e db [2] 58 ee [2] 76 ee [2] 49 f2 }

  condition:
    any of them
}