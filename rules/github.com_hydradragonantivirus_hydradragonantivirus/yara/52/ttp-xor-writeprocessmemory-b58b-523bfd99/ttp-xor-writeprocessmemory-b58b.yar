rule TTP_XOR_WriteProcessMemory_b58b {
  strings:
    $key_b58b = { e2 f9 [2] d0 db [2] d6 ee [2] f8 ee [2] c7 f2 }

  condition:
    any of them
}