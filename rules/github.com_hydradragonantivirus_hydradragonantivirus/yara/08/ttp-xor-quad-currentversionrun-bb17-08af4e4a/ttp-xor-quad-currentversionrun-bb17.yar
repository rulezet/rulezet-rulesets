rule TTP_XOR_QUAD_CurrentVersionRun_bb17 {
  strings:
    $key_bb17 = { e8 78 [2] cc 76 [2] e7 5a [2] c9 78 [2] dd 63 [2] d2 79 [2] cc 64 [2] ce 65 [2] d5 63 [2] c9 64 [2] d5 4b }

  condition:
    any of them
}