rule TTP_XOR_WriteProcessMemory_a08b {
  strings:
    $key_a08b = { f7 f9 [2] c5 db [2] c3 ee [2] ed ee [2] d2 f2 }

  condition:
    any of them
}