rule TTP_XOR_WriteProcessMemory_188b {
  strings:
    $key_188b = { 4f f9 [2] 7d db [2] 7b ee [2] 55 ee [2] 6a f2 }

  condition:
    any of them
}