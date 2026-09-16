rule TTP_XOR_QUAD_CurrentVersionRun_bb61 {
  strings:
    $key_bb61 = { e8 0e [2] cc 00 [2] e7 2c [2] c9 0e [2] dd 15 [2] d2 0f [2] cc 12 [2] ce 13 [2] d5 15 [2] c9 12 [2] d5 3d }

  condition:
    any of them
}