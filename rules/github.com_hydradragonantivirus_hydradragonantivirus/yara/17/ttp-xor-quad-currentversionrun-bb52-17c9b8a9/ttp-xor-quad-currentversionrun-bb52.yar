rule TTP_XOR_QUAD_CurrentVersionRun_bb52 {
  strings:
    $key_bb52 = { e8 3d [2] cc 33 [2] e7 1f [2] c9 3d [2] dd 26 [2] d2 3c [2] cc 21 [2] ce 20 [2] d5 26 [2] c9 21 [2] d5 0e }

  condition:
    any of them
}