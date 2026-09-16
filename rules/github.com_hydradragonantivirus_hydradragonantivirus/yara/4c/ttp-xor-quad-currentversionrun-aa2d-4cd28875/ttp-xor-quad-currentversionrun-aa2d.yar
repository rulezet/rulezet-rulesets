rule TTP_XOR_QUAD_CurrentVersionRun_aa2d {
  strings:
    $key_aa2d = { f9 42 [2] dd 4c [2] f6 60 [2] d8 42 [2] cc 59 [2] c3 43 [2] dd 5e [2] df 5f [2] c4 59 [2] d8 5e [2] c4 71 }

  condition:
    any of them
}