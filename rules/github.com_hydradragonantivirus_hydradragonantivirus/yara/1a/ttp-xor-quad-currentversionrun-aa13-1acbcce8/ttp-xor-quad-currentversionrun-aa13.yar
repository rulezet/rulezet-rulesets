rule TTP_XOR_QUAD_CurrentVersionRun_aa13 {
  strings:
    $key_aa13 = { f9 7c [2] dd 72 [2] f6 5e [2] d8 7c [2] cc 67 [2] c3 7d [2] dd 60 [2] df 61 [2] c4 67 [2] d8 60 [2] c4 4f }

  condition:
    any of them
}