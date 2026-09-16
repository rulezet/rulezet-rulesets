rule TTP_XOR_QUAD_CurrentVersionRun_d6a6 {
  strings:
    $key_d6a6 = { 85 c9 [2] a1 c7 [2] 8a eb [2] a4 c9 [2] b0 d2 [2] bf c8 [2] a1 d5 [2] a3 d4 [2] b8 d2 [2] a4 d5 [2] b8 fa }

  condition:
    any of them
}