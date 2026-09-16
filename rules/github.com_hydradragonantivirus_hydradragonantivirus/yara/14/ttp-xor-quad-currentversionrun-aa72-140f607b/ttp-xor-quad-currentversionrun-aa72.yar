rule TTP_XOR_QUAD_CurrentVersionRun_aa72 {
  strings:
    $key_aa72 = { f9 1d [2] dd 13 [2] f6 3f [2] d8 1d [2] cc 06 [2] c3 1c [2] dd 01 [2] df 00 [2] c4 06 [2] d8 01 [2] c4 2e }

  condition:
    any of them
}