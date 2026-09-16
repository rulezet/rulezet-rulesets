rule TTP_XOR_QUAD_CurrentVersionRun_aa57 {
  strings:
    $key_aa57 = { f9 38 [2] dd 36 [2] f6 1a [2] d8 38 [2] cc 23 [2] c3 39 [2] dd 24 [2] df 25 [2] c4 23 [2] d8 24 [2] c4 0b }

  condition:
    any of them
}