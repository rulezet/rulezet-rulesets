rule TTP_XOR_QUAD_CurrentVersionRun_d9e6 {
  strings:
    $key_d9e6 = { 8a 89 [2] ae 87 [2] 85 ab [2] ab 89 [2] bf 92 [2] b0 88 [2] ae 95 [2] ac 94 [2] b7 92 [2] ab 95 [2] b7 ba }

  condition:
    any of them
}