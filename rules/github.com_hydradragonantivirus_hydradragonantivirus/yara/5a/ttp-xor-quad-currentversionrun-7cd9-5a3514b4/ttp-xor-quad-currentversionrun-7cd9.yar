rule TTP_XOR_QUAD_CurrentVersionRun_7cd9 {
  strings:
    $key_7cd9 = { 2f b6 [2] 0b b8 [2] 20 94 [2] 0e b6 [2] 1a ad [2] 15 b7 [2] 0b aa [2] 09 ab [2] 12 ad [2] 0e aa [2] 12 85 }

  condition:
    any of them
}