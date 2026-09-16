rule TTP_XOR_QUAD_CurrentVersionRun_ee97 {
  strings:
    $key_ee97 = { bd f8 [2] 99 f6 [2] b2 da [2] 9c f8 [2] 88 e3 [2] 87 f9 [2] 99 e4 [2] 9b e5 [2] 80 e3 [2] 9c e4 [2] 80 cb }

  condition:
    any of them
}