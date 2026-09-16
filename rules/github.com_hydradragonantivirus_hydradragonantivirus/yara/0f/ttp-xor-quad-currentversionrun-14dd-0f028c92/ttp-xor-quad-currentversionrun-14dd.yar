rule TTP_XOR_QUAD_CurrentVersionRun_14dd {
  strings:
    $key_14dd = { 47 b2 [2] 63 bc [2] 48 90 [2] 66 b2 [2] 72 a9 [2] 7d b3 [2] 63 ae [2] 61 af [2] 7a a9 [2] 66 ae [2] 7a 81 }

  condition:
    any of them
}