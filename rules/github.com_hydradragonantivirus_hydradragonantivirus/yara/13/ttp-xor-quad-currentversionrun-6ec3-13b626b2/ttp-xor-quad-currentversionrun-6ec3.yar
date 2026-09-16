rule TTP_XOR_QUAD_CurrentVersionRun_6ec3 {
  strings:
    $key_6ec3 = { 3d ac [2] 19 a2 [2] 32 8e [2] 1c ac [2] 08 b7 [2] 07 ad [2] 19 b0 [2] 1b b1 [2] 00 b7 [2] 1c b0 [2] 00 9f }

  condition:
    any of them
}