rule TTP_XOR_QUAD_CurrentVersionRun_fb97 {
  strings:
    $key_fb97 = { a8 f8 [2] 8c f6 [2] a7 da [2] 89 f8 [2] 9d e3 [2] 92 f9 [2] 8c e4 [2] 8e e5 [2] 95 e3 [2] 89 e4 [2] 95 cb }

  condition:
    any of them
}