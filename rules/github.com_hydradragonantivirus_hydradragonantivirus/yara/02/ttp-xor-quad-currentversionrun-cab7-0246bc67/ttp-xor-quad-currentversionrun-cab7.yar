rule TTP_XOR_QUAD_CurrentVersionRun_cab7 {
  strings:
    $key_cab7 = { 99 d8 [2] bd d6 [2] 96 fa [2] b8 d8 [2] ac c3 [2] a3 d9 [2] bd c4 [2] bf c5 [2] a4 c3 [2] b8 c4 [2] a4 eb }

  condition:
    any of them
}