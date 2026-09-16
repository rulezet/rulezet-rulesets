rule TTP_XOR_QUAD_CurrentVersionRun_29ad {
  strings:
    $key_29ad = { 7a c2 [2] 5e cc [2] 75 e0 [2] 5b c2 [2] 4f d9 [2] 40 c3 [2] 5e de [2] 5c df [2] 47 d9 [2] 5b de [2] 47 f1 }

  condition:
    any of them
}