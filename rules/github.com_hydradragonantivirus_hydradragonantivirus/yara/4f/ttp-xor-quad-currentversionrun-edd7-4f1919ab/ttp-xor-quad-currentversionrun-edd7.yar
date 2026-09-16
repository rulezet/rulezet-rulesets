rule TTP_XOR_QUAD_CurrentVersionRun_edd7 {
  strings:
    $key_edd7 = { be b8 [2] 9a b6 [2] b1 9a [2] 9f b8 [2] 8b a3 [2] 84 b9 [2] 9a a4 [2] 98 a5 [2] 83 a3 [2] 9f a4 [2] 83 8b }

  condition:
    any of them
}