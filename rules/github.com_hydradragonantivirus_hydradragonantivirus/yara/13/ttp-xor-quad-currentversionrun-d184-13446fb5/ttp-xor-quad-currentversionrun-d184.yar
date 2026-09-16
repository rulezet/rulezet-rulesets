rule TTP_XOR_QUAD_CurrentVersionRun_d184 {
  strings:
    $key_d184 = { 82 eb [2] a6 e5 [2] 8d c9 [2] a3 eb [2] b7 f0 [2] b8 ea [2] a6 f7 [2] a4 f6 [2] bf f0 [2] a3 f7 [2] bf d8 }

  condition:
    any of them
}