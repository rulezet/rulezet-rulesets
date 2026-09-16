rule TTP_XOR_QUAD_CurrentVersionRun_aa35 {
  strings:
    $key_aa35 = { f9 5a [2] dd 54 [2] f6 78 [2] d8 5a [2] cc 41 [2] c3 5b [2] dd 46 [2] df 47 [2] c4 41 [2] d8 46 [2] c4 69 }

  condition:
    any of them
}