rule TTP_XOR_QUAD_CurrentVersionRun_aa2b {
  strings:
    $key_aa2b = { f9 44 [2] dd 4a [2] f6 66 [2] d8 44 [2] cc 5f [2] c3 45 [2] dd 58 [2] df 59 [2] c4 5f [2] d8 58 [2] c4 77 }

  condition:
    any of them
}