rule TTP_XOR_QUAD_CurrentVersionRun_48c5 {
  strings:
    $key_48c5 = { 1b aa [2] 3f a4 [2] 14 88 [2] 3a aa [2] 2e b1 [2] 21 ab [2] 3f b6 [2] 3d b7 [2] 26 b1 [2] 3a b6 [2] 26 99 }

  condition:
    any of them
}