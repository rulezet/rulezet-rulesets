rule TTP_XOR_QUAD_CurrentVersionRun_58c5 {
  strings:
    $key_58c5 = { 0b aa [2] 2f a4 [2] 04 88 [2] 2a aa [2] 3e b1 [2] 31 ab [2] 2f b6 [2] 2d b7 [2] 36 b1 [2] 2a b6 [2] 36 99 }

  condition:
    any of them
}