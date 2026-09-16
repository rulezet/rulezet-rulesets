rule TTP_XOR_QUAD_CurrentVersionRun_def3 {
  strings:
    $key_def3 = { 8d 9c [2] a9 92 [2] 82 be [2] ac 9c [2] b8 87 [2] b7 9d [2] a9 80 [2] ab 81 [2] b0 87 [2] ac 80 [2] b0 af }

  condition:
    any of them
}