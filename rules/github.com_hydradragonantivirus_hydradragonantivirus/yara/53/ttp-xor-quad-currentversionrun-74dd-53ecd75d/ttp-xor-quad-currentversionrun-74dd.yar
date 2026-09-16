rule TTP_XOR_QUAD_CurrentVersionRun_74dd {
  strings:
    $key_74dd = { 27 b2 [2] 03 bc [2] 28 90 [2] 06 b2 [2] 12 a9 [2] 1d b3 [2] 03 ae [2] 01 af [2] 1a a9 [2] 06 ae [2] 1a 81 }

  condition:
    any of them
}