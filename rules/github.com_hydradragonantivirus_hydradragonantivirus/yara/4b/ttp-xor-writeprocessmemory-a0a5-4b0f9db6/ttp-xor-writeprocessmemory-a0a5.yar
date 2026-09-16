rule TTP_XOR_WriteProcessMemory_a0a5 {
  strings:
    $key_a0a5 = { f7 d7 [2] c5 f5 [2] c3 c0 [2] ed c0 [2] d2 dc }

  condition:
    any of them
}