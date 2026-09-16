rule TTP_XOR_QUAD_CurrentVersionRun_d843 {
  strings:
    $key_d843 = { 8b 2c [2] af 22 [2] 84 0e [2] aa 2c [2] be 37 [2] b1 2d [2] af 30 [2] ad 31 [2] b6 37 [2] aa 30 [2] b6 1f }

  condition:
    any of them
}