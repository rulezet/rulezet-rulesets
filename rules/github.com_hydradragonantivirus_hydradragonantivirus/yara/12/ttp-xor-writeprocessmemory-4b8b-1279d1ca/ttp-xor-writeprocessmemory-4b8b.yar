rule TTP_XOR_WriteProcessMemory_4b8b {
  strings:
    $key_4b8b = { 1c f9 [2] 2e db [2] 28 ee [2] 06 ee [2] 39 f2 }

  condition:
    any of them
}