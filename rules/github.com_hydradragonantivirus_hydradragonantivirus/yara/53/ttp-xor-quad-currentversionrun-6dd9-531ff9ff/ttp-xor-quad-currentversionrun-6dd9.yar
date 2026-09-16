rule TTP_XOR_QUAD_CurrentVersionRun_6dd9 {
  strings:
    $key_6dd9 = { 3e b6 [2] 1a b8 [2] 31 94 [2] 1f b6 [2] 0b ad [2] 04 b7 [2] 1a aa [2] 18 ab [2] 03 ad [2] 1f aa [2] 03 85 }

  condition:
    any of them
}