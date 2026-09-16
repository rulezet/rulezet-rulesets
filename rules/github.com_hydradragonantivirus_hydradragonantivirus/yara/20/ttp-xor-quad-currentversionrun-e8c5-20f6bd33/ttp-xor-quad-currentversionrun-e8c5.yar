rule TTP_XOR_QUAD_CurrentVersionRun_e8c5 {
  strings:
    $key_e8c5 = { bb aa [2] 9f a4 [2] b4 88 [2] 9a aa [2] 8e b1 [2] 81 ab [2] 9f b6 [2] 9d b7 [2] 86 b1 [2] 9a b6 [2] 86 99 }

  condition:
    any of them
}