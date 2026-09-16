rule TTP_XOR_QUAD_CurrentVersionRun_0dd9 {
  strings:
    $key_0dd9 = { 5e b6 [2] 7a b8 [2] 51 94 [2] 7f b6 [2] 6b ad [2] 64 b7 [2] 7a aa [2] 78 ab [2] 63 ad [2] 7f aa [2] 63 85 }

  condition:
    any of them
}