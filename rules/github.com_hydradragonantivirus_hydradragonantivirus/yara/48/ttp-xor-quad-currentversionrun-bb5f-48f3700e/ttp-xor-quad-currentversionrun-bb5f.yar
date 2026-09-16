rule TTP_XOR_QUAD_CurrentVersionRun_bb5f {
  strings:
    $key_bb5f = { e8 30 [2] cc 3e [2] e7 12 [2] c9 30 [2] dd 2b [2] d2 31 [2] cc 2c [2] ce 2d [2] d5 2b [2] c9 2c [2] d5 03 }

  condition:
    any of them
}