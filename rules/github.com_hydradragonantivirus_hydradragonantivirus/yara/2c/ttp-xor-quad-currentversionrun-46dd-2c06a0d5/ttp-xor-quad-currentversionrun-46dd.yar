rule TTP_XOR_QUAD_CurrentVersionRun_46dd {
  strings:
    $key_46dd = { 15 b2 [2] 31 bc [2] 1a 90 [2] 34 b2 [2] 20 a9 [2] 2f b3 [2] 31 ae [2] 33 af [2] 28 a9 [2] 34 ae [2] 28 81 }

  condition:
    any of them
}