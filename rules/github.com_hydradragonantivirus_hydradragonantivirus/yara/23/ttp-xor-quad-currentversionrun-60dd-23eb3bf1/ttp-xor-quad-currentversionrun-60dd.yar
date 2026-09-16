rule TTP_XOR_QUAD_CurrentVersionRun_60dd {
  strings:
    $key_60dd = { 33 b2 [2] 17 bc [2] 3c 90 [2] 12 b2 [2] 06 a9 [2] 09 b3 [2] 17 ae [2] 15 af [2] 0e a9 [2] 12 ae [2] 0e 81 }

  condition:
    any of them
}