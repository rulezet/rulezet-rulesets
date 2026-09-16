rule TTP_XOR_QUAD_CurrentVersionRun_d9f5 {
  strings:
    $key_d9f5 = { 8a 9a [2] ae 94 [2] 85 b8 [2] ab 9a [2] bf 81 [2] b0 9b [2] ae 86 [2] ac 87 [2] b7 81 [2] ab 86 [2] b7 a9 }

  condition:
    any of them
}