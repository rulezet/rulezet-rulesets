rule TTP_XOR_QUAD_CurrentVersionRun_d626 {
  strings:
    $key_d626 = { 85 49 [2] a1 47 [2] 8a 6b [2] a4 49 [2] b0 52 [2] bf 48 [2] a1 55 [2] a3 54 [2] b8 52 [2] a4 55 [2] b8 7a }

  condition:
    any of them
}