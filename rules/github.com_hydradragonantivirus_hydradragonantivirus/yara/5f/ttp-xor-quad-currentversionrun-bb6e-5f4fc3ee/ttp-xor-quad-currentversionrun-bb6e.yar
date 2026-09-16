rule TTP_XOR_QUAD_CurrentVersionRun_bb6e {
  strings:
    $key_bb6e = { e8 01 [2] cc 0f [2] e7 23 [2] c9 01 [2] dd 1a [2] d2 00 [2] cc 1d [2] ce 1c [2] d5 1a [2] c9 1d [2] d5 32 }

  condition:
    any of them
}