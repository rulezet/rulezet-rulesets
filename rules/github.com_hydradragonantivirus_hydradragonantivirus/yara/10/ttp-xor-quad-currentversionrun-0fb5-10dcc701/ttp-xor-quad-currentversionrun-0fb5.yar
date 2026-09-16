rule TTP_XOR_QUAD_CurrentVersionRun_0fb5 {
  strings:
    $key_0fb5 = { 5c da [2] 78 d4 [2] 53 f8 [2] 7d da [2] 69 c1 [2] 66 db [2] 78 c6 [2] 7a c7 [2] 61 c1 [2] 7d c6 [2] 61 e9 }

  condition:
    any of them
}