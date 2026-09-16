rule TTP_XOR_QUAD_CurrentVersionRun_68d9 {
  strings:
    $key_68d9 = { 3b b6 [2] 1f b8 [2] 34 94 [2] 1a b6 [2] 0e ad [2] 01 b7 [2] 1f aa [2] 1d ab [2] 06 ad [2] 1a aa [2] 06 85 }

  condition:
    any of them
}