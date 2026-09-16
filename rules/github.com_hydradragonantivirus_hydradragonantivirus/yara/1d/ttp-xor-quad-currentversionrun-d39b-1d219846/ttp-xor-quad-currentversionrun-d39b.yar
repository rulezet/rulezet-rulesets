rule TTP_XOR_QUAD_CurrentVersionRun_d39b {
  strings:
    $key_d39b = { 80 f4 [2] a4 fa [2] 8f d6 [2] a1 f4 [2] b5 ef [2] ba f5 [2] a4 e8 [2] a6 e9 [2] bd ef [2] a1 e8 [2] bd c7 }

  condition:
    any of them
}