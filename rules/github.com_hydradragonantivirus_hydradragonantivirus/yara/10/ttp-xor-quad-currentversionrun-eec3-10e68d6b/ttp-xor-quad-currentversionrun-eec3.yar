rule TTP_XOR_QUAD_CurrentVersionRun_eec3 {
  strings:
    $key_eec3 = { bd ac [2] 99 a2 [2] b2 8e [2] 9c ac [2] 88 b7 [2] 87 ad [2] 99 b0 [2] 9b b1 [2] 80 b7 [2] 9c b0 [2] 80 9f }

  condition:
    any of them
}