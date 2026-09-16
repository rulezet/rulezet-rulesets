rule TTP_XOR_QUAD_CurrentVersionRun_db9b {
  strings:
    $key_db9b = { 88 f4 [2] ac fa [2] 87 d6 [2] a9 f4 [2] bd ef [2] b2 f5 [2] ac e8 [2] ae e9 [2] b5 ef [2] a9 e8 [2] b5 c7 }

  condition:
    any of them
}