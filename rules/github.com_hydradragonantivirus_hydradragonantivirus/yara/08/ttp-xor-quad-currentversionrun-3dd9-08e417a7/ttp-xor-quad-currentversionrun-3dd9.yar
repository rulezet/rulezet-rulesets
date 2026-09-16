rule TTP_XOR_QUAD_CurrentVersionRun_3dd9 {
  strings:
    $key_3dd9 = { 6e b6 [2] 4a b8 [2] 61 94 [2] 4f b6 [2] 5b ad [2] 54 b7 [2] 4a aa [2] 48 ab [2] 53 ad [2] 4f aa [2] 53 85 }

  condition:
    any of them
}