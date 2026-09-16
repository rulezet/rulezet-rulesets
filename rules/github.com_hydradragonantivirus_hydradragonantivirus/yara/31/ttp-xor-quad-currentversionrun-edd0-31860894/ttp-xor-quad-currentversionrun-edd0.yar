rule TTP_XOR_QUAD_CurrentVersionRun_edd0 {
  strings:
    $key_edd0 = { be bf [2] 9a b1 [2] b1 9d [2] 9f bf [2] 8b a4 [2] 84 be [2] 9a a3 [2] 98 a2 [2] 83 a4 [2] 9f a3 [2] 83 8c }

  condition:
    any of them
}