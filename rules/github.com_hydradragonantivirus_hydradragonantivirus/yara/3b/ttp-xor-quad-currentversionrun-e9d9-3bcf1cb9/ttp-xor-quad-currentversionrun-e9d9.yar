rule TTP_XOR_QUAD_CurrentVersionRun_e9d9 {
  strings:
    $key_e9d9 = { ba b6 [2] 9e b8 [2] b5 94 [2] 9b b6 [2] 8f ad [2] 80 b7 [2] 9e aa [2] 9c ab [2] 87 ad [2] 9b aa [2] 87 85 }

  condition:
    any of them
}