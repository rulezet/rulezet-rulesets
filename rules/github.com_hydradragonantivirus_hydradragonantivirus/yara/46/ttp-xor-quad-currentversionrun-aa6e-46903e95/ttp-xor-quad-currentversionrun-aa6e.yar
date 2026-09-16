rule TTP_XOR_QUAD_CurrentVersionRun_aa6e {
  strings:
    $key_aa6e = { f9 01 [2] dd 0f [2] f6 23 [2] d8 01 [2] cc 1a [2] c3 00 [2] dd 1d [2] df 1c [2] c4 1a [2] d8 1d [2] c4 32 }

  condition:
    any of them
}