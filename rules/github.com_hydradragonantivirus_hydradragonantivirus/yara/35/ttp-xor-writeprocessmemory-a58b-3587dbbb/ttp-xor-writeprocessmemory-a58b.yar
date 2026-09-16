rule TTP_XOR_WriteProcessMemory_a58b {
  strings:
    $key_a58b = { f2 f9 [2] c0 db [2] c6 ee [2] e8 ee [2] d7 f2 }

  condition:
    any of them
}