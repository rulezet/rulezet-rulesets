rule TTP_XOR_QUAD_CurrentVersionRun_aa65 {
  strings:
    $key_aa65 = { f9 0a [2] dd 04 [2] f6 28 [2] d8 0a [2] cc 11 [2] c3 0b [2] dd 16 [2] df 17 [2] c4 11 [2] d8 16 [2] c4 39 }

  condition:
    any of them
}