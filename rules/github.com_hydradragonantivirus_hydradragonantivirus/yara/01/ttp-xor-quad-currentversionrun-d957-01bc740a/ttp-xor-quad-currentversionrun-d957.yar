rule TTP_XOR_QUAD_CurrentVersionRun_d957 {
  strings:
    $key_d957 = { 8a 38 [2] ae 36 [2] 85 1a [2] ab 38 [2] bf 23 [2] b0 39 [2] ae 24 [2] ac 25 [2] b7 23 [2] ab 24 [2] b7 0b }

  condition:
    any of them
}