rule TTP_XOR_QUAD_CurrentVersionRun_aa04 {
  strings:
    $key_aa04 = { f9 6b [2] dd 65 [2] f6 49 [2] d8 6b [2] cc 70 [2] c3 6a [2] dd 77 [2] df 76 [2] c4 70 [2] d8 77 [2] c4 58 }

  condition:
    any of them
}