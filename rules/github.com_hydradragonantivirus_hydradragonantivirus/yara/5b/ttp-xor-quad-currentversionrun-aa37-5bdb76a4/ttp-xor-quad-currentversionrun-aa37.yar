rule TTP_XOR_QUAD_CurrentVersionRun_aa37 {
  strings:
    $key_aa37 = { f9 58 [2] dd 56 [2] f6 7a [2] d8 58 [2] cc 43 [2] c3 59 [2] dd 44 [2] df 45 [2] c4 43 [2] d8 44 [2] c4 6b }

  condition:
    any of them
}