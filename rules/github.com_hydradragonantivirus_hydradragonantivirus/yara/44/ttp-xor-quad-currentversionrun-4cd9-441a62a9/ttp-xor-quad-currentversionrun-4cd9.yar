rule TTP_XOR_QUAD_CurrentVersionRun_4cd9 {
  strings:
    $key_4cd9 = { 1f b6 [2] 3b b8 [2] 10 94 [2] 3e b6 [2] 2a ad [2] 25 b7 [2] 3b aa [2] 39 ab [2] 22 ad [2] 3e aa [2] 22 85 }

  condition:
    any of them
}