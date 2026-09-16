rule TTP_XOR_QUAD_CurrentVersionRun_d997 {
  strings:
    $key_d997 = { 8a f8 [2] ae f6 [2] 85 da [2] ab f8 [2] bf e3 [2] b0 f9 [2] ae e4 [2] ac e5 [2] b7 e3 [2] ab e4 [2] b7 cb }

  condition:
    any of them
}