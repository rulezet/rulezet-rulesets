rule TTP_XOR_QUAD_CurrentVersionRun_bb71 {
  strings:
    $key_bb71 = { e8 1e [2] cc 10 [2] e7 3c [2] c9 1e [2] dd 05 [2] d2 1f [2] cc 02 [2] ce 03 [2] d5 05 [2] c9 02 [2] d5 2d }

  condition:
    any of them
}