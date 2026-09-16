rule TTP_XOR_QUAD_CurrentVersionRun_ca87 {
  strings:
    $key_ca87 = { 99 e8 [2] bd e6 [2] 96 ca [2] b8 e8 [2] ac f3 [2] a3 e9 [2] bd f4 [2] bf f5 [2] a4 f3 [2] b8 f4 [2] a4 db }

  condition:
    any of them
}