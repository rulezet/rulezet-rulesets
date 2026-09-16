rule TTP_XOR_QUAD_CurrentVersionRun_d6b4 {
  strings:
    $key_d6b4 = { 85 db [2] a1 d5 [2] 8a f9 [2] a4 db [2] b0 c0 [2] bf da [2] a1 c7 [2] a3 c6 [2] b8 c0 [2] a4 c7 [2] b8 e8 }

  condition:
    any of them
}