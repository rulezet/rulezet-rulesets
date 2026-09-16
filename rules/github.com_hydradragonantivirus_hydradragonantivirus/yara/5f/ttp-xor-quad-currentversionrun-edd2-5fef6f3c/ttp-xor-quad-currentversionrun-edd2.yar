rule TTP_XOR_QUAD_CurrentVersionRun_edd2 {
  strings:
    $key_edd2 = { be bd [2] 9a b3 [2] b1 9f [2] 9f bd [2] 8b a6 [2] 84 bc [2] 9a a1 [2] 98 a0 [2] 83 a6 [2] 9f a1 [2] 83 8e }

  condition:
    any of them
}