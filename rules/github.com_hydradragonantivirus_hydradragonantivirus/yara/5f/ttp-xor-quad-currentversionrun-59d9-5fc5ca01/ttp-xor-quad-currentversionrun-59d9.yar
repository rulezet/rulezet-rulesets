rule TTP_XOR_QUAD_CurrentVersionRun_59d9 {
  strings:
    $key_59d9 = { 0a b6 [2] 2e b8 [2] 05 94 [2] 2b b6 [2] 3f ad [2] 30 b7 [2] 2e aa [2] 2c ab [2] 37 ad [2] 2b aa [2] 37 85 }

  condition:
    any of them
}