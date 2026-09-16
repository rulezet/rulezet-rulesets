rule TTP_XOR_QUAD_CurrentVersionRun_caa6 {
  strings:
    $key_caa6 = { 99 c9 [2] bd c7 [2] 96 eb [2] b8 c9 [2] ac d2 [2] a3 c8 [2] bd d5 [2] bf d4 [2] a4 d2 [2] b8 d5 [2] a4 fa }

  condition:
    any of them
}