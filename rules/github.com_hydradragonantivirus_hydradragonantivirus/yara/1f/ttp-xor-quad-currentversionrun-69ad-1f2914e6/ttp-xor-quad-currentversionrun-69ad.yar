rule TTP_XOR_QUAD_CurrentVersionRun_69ad {
  strings:
    $key_69ad = { 3a c2 [2] 1e cc [2] 35 e0 [2] 1b c2 [2] 0f d9 [2] 00 c3 [2] 1e de [2] 1c df [2] 07 d9 [2] 1b de [2] 07 f1 }

  condition:
    any of them
}