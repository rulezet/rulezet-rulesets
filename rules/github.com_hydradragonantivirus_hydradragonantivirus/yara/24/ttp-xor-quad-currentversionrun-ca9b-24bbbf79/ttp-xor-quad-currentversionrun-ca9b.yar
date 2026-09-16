rule TTP_XOR_QUAD_CurrentVersionRun_ca9b {
  strings:
    $key_ca9b = { 99 f4 [2] bd fa [2] 96 d6 [2] b8 f4 [2] ac ef [2] a3 f5 [2] bd e8 [2] bf e9 [2] a4 ef [2] b8 e8 [2] a4 c7 }

  condition:
    any of them
}