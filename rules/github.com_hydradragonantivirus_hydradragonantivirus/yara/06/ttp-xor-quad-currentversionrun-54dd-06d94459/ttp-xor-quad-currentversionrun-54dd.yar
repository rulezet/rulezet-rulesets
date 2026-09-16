rule TTP_XOR_QUAD_CurrentVersionRun_54dd {
  strings:
    $key_54dd = { 07 b2 [2] 23 bc [2] 08 90 [2] 26 b2 [2] 32 a9 [2] 3d b3 [2] 23 ae [2] 21 af [2] 3a a9 [2] 26 ae [2] 3a 81 }

  condition:
    any of them
}