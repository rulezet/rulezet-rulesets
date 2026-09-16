rule TTP_XOR_QUAD_CurrentVersionRun_c8dd {
  strings:
    $key_c8dd = { 9b b2 [2] bf bc [2] 94 90 [2] ba b2 [2] ae a9 [2] a1 b3 [2] bf ae [2] bd af [2] a6 a9 [2] ba ae [2] a6 81 }

  condition:
    any of them
}