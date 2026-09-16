rule TTP_XOR_WriteProcessMemory_6e8b {
  strings:
    $key_6e8b = { 39 f9 [2] 0b db [2] 0d ee [2] 23 ee [2] 1c f2 }

  condition:
    any of them
}