rule TTP_XOR_QUAD_CurrentVersionRun_aa24 {
  strings:
    $key_aa24 = { f9 4b [2] dd 45 [2] f6 69 [2] d8 4b [2] cc 50 [2] c3 4a [2] dd 57 [2] df 56 [2] c4 50 [2] d8 57 [2] c4 78 }

  condition:
    any of them
}