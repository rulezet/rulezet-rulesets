rule TTP_XOR_WriteProcessMemory_a78b {
  strings:
    $key_a78b = { f0 f9 [2] c2 db [2] c4 ee [2] ea ee [2] d5 f2 }

  condition:
    any of them
}