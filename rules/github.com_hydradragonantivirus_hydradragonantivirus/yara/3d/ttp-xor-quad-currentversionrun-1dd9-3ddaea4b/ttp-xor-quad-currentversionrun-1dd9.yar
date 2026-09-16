rule TTP_XOR_QUAD_CurrentVersionRun_1dd9 {
  strings:
    $key_1dd9 = { 4e b6 [2] 6a b8 [2] 41 94 [2] 6f b6 [2] 7b ad [2] 74 b7 [2] 6a aa [2] 68 ab [2] 73 ad [2] 6f aa [2] 73 85 }

  condition:
    any of them
}