rule TTP_XOR_QUAD_CurrentVersionRun_bb49 {
  strings:
    $key_bb49 = { e8 26 [2] cc 28 [2] e7 04 [2] c9 26 [2] dd 3d [2] d2 27 [2] cc 3a [2] ce 3b [2] d5 3d [2] c9 3a [2] d5 15 }

  condition:
    any of them
}