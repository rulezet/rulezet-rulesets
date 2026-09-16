rule TTP_XOR_QUAD_CurrentVersionRun_6cd9 {
  strings:
    $key_6cd9 = { 3f b6 [2] 1b b8 [2] 30 94 [2] 1e b6 [2] 0a ad [2] 05 b7 [2] 1b aa [2] 19 ab [2] 02 ad [2] 1e aa [2] 02 85 }

  condition:
    any of them
}