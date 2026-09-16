rule TTP_XOR_WriteProcessMemory_a080 {
  strings:
    $key_a080 = { f7 f2 [2] c5 d0 [2] c3 e5 [2] ed e5 [2] d2 f9 }

  condition:
    any of them
}