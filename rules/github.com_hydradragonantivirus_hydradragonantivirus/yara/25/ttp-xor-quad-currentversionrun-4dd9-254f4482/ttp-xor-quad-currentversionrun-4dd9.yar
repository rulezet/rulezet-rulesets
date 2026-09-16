rule TTP_XOR_QUAD_CurrentVersionRun_4dd9 {
  strings:
    $key_4dd9 = { 1e b6 [2] 3a b8 [2] 11 94 [2] 3f b6 [2] 2b ad [2] 24 b7 [2] 3a aa [2] 38 ab [2] 23 ad [2] 3f aa [2] 23 85 }

  condition:
    any of them
}