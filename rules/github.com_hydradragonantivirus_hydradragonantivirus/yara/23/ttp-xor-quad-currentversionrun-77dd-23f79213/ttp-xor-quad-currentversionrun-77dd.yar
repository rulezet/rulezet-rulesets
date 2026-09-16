rule TTP_XOR_QUAD_CurrentVersionRun_77dd {
  strings:
    $key_77dd = { 24 b2 [2] 00 bc [2] 2b 90 [2] 05 b2 [2] 11 a9 [2] 1e b3 [2] 00 ae [2] 02 af [2] 19 a9 [2] 05 ae [2] 19 81 }

  condition:
    any of them
}