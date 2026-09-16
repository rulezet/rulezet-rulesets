rule TTP_XOR_QUAD_CurrentVersionRun_76dd {
  strings:
    $key_76dd = { 25 b2 [2] 01 bc [2] 2a 90 [2] 04 b2 [2] 10 a9 [2] 1f b3 [2] 01 ae [2] 03 af [2] 18 a9 [2] 04 ae [2] 18 81 }

  condition:
    any of them
}