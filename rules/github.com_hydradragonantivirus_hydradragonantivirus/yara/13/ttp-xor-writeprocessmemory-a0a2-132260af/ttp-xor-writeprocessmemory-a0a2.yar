rule TTP_XOR_WriteProcessMemory_a0a2 {
  strings:
    $key_a0a2 = { f7 d0 [2] c5 f2 [2] c3 c7 [2] ed c7 [2] d2 db }

  condition:
    any of them
}