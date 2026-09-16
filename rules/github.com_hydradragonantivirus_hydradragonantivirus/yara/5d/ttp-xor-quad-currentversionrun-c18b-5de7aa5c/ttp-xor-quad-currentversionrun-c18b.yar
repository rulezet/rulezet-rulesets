rule TTP_XOR_QUAD_CurrentVersionRun_c18b {
  strings:
    $key_c18b = { 92 e4 [2] b6 ea [2] 9d c6 [2] b3 e4 [2] a7 ff [2] a8 e5 [2] b6 f8 [2] b4 f9 [2] af ff [2] b3 f8 [2] af d7 }

  condition:
    any of them
}