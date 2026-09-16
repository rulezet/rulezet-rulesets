rule TTP_XOR_QUAD_CurrentVersionRun_aa73 {
  strings:
    $key_aa73 = { f9 1c [2] dd 12 [2] f6 3e [2] d8 1c [2] cc 07 [2] c3 1d [2] dd 00 [2] df 01 [2] c4 07 [2] d8 00 [2] c4 2f }

  condition:
    any of them
}