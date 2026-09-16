rule TTP_XOR_QUAD_CurrentVersionRun_59ad {
  strings:
    $key_59ad = { 0a c2 [2] 2e cc [2] 05 e0 [2] 2b c2 [2] 3f d9 [2] 30 c3 [2] 2e de [2] 2c df [2] 37 d9 [2] 2b de [2] 37 f1 }

  condition:
    any of them
}