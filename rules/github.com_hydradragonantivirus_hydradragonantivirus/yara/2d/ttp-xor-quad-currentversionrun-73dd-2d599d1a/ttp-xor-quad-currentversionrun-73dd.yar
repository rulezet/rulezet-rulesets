rule TTP_XOR_QUAD_CurrentVersionRun_73dd {
  strings:
    $key_73dd = { 20 b2 [2] 04 bc [2] 2f 90 [2] 01 b2 [2] 15 a9 [2] 1a b3 [2] 04 ae [2] 06 af [2] 1d a9 [2] 01 ae [2] 1d 81 }

  condition:
    any of them
}