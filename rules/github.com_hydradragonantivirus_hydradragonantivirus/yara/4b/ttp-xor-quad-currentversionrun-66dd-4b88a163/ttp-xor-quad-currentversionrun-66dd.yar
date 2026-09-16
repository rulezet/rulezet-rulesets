rule TTP_XOR_QUAD_CurrentVersionRun_66dd {
  strings:
    $key_66dd = { 35 b2 [2] 11 bc [2] 3a 90 [2] 14 b2 [2] 00 a9 [2] 0f b3 [2] 11 ae [2] 13 af [2] 08 a9 [2] 14 ae [2] 08 81 }

  condition:
    any of them
}