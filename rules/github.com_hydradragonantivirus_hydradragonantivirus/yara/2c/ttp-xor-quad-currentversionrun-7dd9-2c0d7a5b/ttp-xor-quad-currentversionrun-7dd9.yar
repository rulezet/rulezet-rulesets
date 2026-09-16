rule TTP_XOR_QUAD_CurrentVersionRun_7dd9 {
  strings:
    $key_7dd9 = { 2e b6 [2] 0a b8 [2] 21 94 [2] 0f b6 [2] 1b ad [2] 14 b7 [2] 0a aa [2] 08 ab [2] 13 ad [2] 0f aa [2] 13 85 }

  condition:
    any of them
}