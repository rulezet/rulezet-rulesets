rule TTP_XOR_WriteProcessMemory_1b8b {
  strings:
    $key_1b8b = { 4c f9 [2] 7e db [2] 78 ee [2] 56 ee [2] 69 f2 }

  condition:
    any of them
}