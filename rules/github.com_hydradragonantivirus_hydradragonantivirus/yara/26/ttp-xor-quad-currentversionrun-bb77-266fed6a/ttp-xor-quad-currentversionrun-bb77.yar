rule TTP_XOR_QUAD_CurrentVersionRun_bb77 {
  strings:
    $key_bb77 = { e8 18 [2] cc 16 [2] e7 3a [2] c9 18 [2] dd 03 [2] d2 19 [2] cc 04 [2] ce 05 [2] d5 03 [2] c9 04 [2] d5 2b }

  condition:
    any of them
}