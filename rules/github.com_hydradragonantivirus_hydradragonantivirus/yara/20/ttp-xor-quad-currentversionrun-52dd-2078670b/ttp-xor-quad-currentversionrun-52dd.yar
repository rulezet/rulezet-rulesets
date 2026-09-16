rule TTP_XOR_QUAD_CurrentVersionRun_52dd {
  strings:
    $key_52dd = { 01 b2 [2] 25 bc [2] 0e 90 [2] 20 b2 [2] 34 a9 [2] 3b b3 [2] 25 ae [2] 27 af [2] 3c a9 [2] 20 ae [2] 3c 81 }

  condition:
    any of them
}