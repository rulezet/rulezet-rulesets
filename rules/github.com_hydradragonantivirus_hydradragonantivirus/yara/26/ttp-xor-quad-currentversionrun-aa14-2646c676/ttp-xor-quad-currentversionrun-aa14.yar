rule TTP_XOR_QUAD_CurrentVersionRun_aa14 {
  strings:
    $key_aa14 = { f9 7b [2] dd 75 [2] f6 59 [2] d8 7b [2] cc 60 [2] c3 7a [2] dd 67 [2] df 66 [2] c4 60 [2] d8 67 [2] c4 48 }

  condition:
    any of them
}