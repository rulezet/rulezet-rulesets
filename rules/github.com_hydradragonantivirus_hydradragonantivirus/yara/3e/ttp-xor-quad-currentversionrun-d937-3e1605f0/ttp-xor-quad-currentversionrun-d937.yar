rule TTP_XOR_QUAD_CurrentVersionRun_d937 {
  strings:
    $key_d937 = { 8a 58 [2] ae 56 [2] 85 7a [2] ab 58 [2] bf 43 [2] b0 59 [2] ae 44 [2] ac 45 [2] b7 43 [2] ab 44 [2] b7 6b }

  condition:
    any of them
}