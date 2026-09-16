rule TTP_XOR_QUAD_CurrentVersionRun_42dd {
  strings:
    $key_42dd = { 11 b2 [2] 35 bc [2] 1e 90 [2] 30 b2 [2] 24 a9 [2] 2b b3 [2] 35 ae [2] 37 af [2] 2c a9 [2] 30 ae [2] 2c 81 }

  condition:
    any of them
}