rule TTP_XOR_QUAD_CurrentVersionRun_d9f8 {
  strings:
    $key_d9f8 = { 8a 97 [2] ae 99 [2] 85 b5 [2] ab 97 [2] bf 8c [2] b0 96 [2] ae 8b [2] ac 8a [2] b7 8c [2] ab 8b [2] b7 a4 }

  condition:
    any of them
}