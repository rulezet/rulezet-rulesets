rule TTP_XOR_QUAD_CurrentVersionRun_aa46 {
  strings:
    $key_aa46 = { f9 29 [2] dd 27 [2] f6 0b [2] d8 29 [2] cc 32 [2] c3 28 [2] dd 35 [2] df 34 [2] c4 32 [2] d8 35 [2] c4 1a }

  condition:
    any of them
}