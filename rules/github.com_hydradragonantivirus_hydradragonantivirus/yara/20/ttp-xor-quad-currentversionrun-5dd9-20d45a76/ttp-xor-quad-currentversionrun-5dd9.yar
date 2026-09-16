rule TTP_XOR_QUAD_CurrentVersionRun_5dd9 {
  strings:
    $key_5dd9 = { 0e b6 [2] 2a b8 [2] 01 94 [2] 2f b6 [2] 3b ad [2] 34 b7 [2] 2a aa [2] 28 ab [2] 33 ad [2] 2f aa [2] 33 85 }

  condition:
    any of them
}