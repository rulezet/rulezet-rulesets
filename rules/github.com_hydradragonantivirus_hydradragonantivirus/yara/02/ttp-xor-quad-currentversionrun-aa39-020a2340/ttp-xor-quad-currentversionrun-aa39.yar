rule TTP_XOR_QUAD_CurrentVersionRun_aa39 {
  strings:
    $key_aa39 = { f9 56 [2] dd 58 [2] f6 74 [2] d8 56 [2] cc 4d [2] c3 57 [2] dd 4a [2] df 4b [2] c4 4d [2] d8 4a [2] c4 65 }

  condition:
    any of them
}