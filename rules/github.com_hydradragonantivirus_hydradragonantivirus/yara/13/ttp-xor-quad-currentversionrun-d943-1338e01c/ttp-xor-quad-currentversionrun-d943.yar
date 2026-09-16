rule TTP_XOR_QUAD_CurrentVersionRun_d943 {
  strings:
    $key_d943 = { 8a 2c [2] ae 22 [2] 85 0e [2] ab 2c [2] bf 37 [2] b0 2d [2] ae 30 [2] ac 31 [2] b7 37 [2] ab 30 [2] b7 1f }

  condition:
    any of them
}