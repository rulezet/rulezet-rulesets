rule TTP_XOR_QUAD_CurrentVersionRun_d99b {
  strings:
    $key_d99b = { 8a f4 [2] ae fa [2] 85 d6 [2] ab f4 [2] bf ef [2] b0 f5 [2] ae e8 [2] ac e9 [2] b7 ef [2] ab e8 [2] b7 c7 }

  condition:
    any of them
}