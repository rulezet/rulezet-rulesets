rule TTP_XOR_QUAD_CurrentVersionRun_79ad {
  strings:
    $key_79ad = { 2a c2 [2] 0e cc [2] 25 e0 [2] 0b c2 [2] 1f d9 [2] 10 c3 [2] 0e de [2] 0c df [2] 17 d9 [2] 0b de [2] 17 f1 }

  condition:
    any of them
}