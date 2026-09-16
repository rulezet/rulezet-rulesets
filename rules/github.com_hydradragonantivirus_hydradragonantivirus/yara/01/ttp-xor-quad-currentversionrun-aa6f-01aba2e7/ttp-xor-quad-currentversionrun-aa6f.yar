rule TTP_XOR_QUAD_CurrentVersionRun_aa6f {
  strings:
    $key_aa6f = { f9 00 [2] dd 0e [2] f6 22 [2] d8 00 [2] cc 1b [2] c3 01 [2] dd 1c [2] df 1d [2] c4 1b [2] d8 1c [2] c4 33 }

  condition:
    any of them
}