rule TTP_XOR_QUAD_CurrentVersionRun_bb6f {
  strings:
    $key_bb6f = { e8 00 [2] cc 0e [2] e7 22 [2] c9 00 [2] dd 1b [2] d2 01 [2] cc 1c [2] ce 1d [2] d5 1b [2] c9 1c [2] d5 33 }

  condition:
    any of them
}