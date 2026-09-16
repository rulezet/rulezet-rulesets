rule TTP_XOR_QUAD_CurrentVersionRun_aa68 {
  strings:
    $key_aa68 = { f9 07 [2] dd 09 [2] f6 25 [2] d8 07 [2] cc 1c [2] c3 06 [2] dd 1b [2] df 1a [2] c4 1c [2] d8 1b [2] c4 34 }

  condition:
    any of them
}