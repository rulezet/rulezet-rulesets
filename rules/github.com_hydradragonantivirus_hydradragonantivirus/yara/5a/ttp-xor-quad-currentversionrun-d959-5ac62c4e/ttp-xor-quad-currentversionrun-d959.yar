rule TTP_XOR_QUAD_CurrentVersionRun_d959 {
  strings:
    $key_d959 = { 8a 36 [2] ae 38 [2] 85 14 [2] ab 36 [2] bf 2d [2] b0 37 [2] ae 2a [2] ac 2b [2] b7 2d [2] ab 2a [2] b7 05 }

  condition:
    any of them
}