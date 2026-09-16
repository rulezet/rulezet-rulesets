rule TTP_XOR_QUAD_CurrentVersionRun_edd4 {
  strings:
    $key_edd4 = { be bb [2] 9a b5 [2] b1 99 [2] 9f bb [2] 8b a0 [2] 84 ba [2] 9a a7 [2] 98 a6 [2] 83 a0 [2] 9f a7 [2] 83 88 }

  condition:
    any of them
}