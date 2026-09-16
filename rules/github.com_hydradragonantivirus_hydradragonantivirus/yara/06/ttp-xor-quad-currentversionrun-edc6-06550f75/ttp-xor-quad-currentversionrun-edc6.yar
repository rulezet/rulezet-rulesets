rule TTP_XOR_QUAD_CurrentVersionRun_edc6 {
  strings:
    $key_edc6 = { be a9 [2] 9a a7 [2] b1 8b [2] 9f a9 [2] 8b b2 [2] 84 a8 [2] 9a b5 [2] 98 b4 [2] 83 b2 [2] 9f b5 [2] 83 9a }

  condition:
    any of them
}