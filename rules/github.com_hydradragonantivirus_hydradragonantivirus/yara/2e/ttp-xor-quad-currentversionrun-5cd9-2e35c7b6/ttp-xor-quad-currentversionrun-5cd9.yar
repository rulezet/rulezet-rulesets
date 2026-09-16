rule TTP_XOR_QUAD_CurrentVersionRun_5cd9 {
  strings:
    $key_5cd9 = { 0f b6 [2] 2b b8 [2] 00 94 [2] 2e b6 [2] 3a ad [2] 35 b7 [2] 2b aa [2] 29 ab [2] 32 ad [2] 2e aa [2] 32 85 }

  condition:
    any of them
}