rule TTP_XOR_QUAD_CurrentVersionRun_edc7 {
  strings:
    $key_edc7 = { be a8 [2] 9a a6 [2] b1 8a [2] 9f a8 [2] 8b b3 [2] 84 a9 [2] 9a b4 [2] 98 b5 [2] 83 b3 [2] 9f b4 [2] 83 9b }

  condition:
    any of them
}