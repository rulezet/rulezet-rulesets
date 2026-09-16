rule TTP_XOR_QUAD_CurrentVersionRun_caa8 {
  strings:
    $key_caa8 = { 99 c7 [2] bd c9 [2] 96 e5 [2] b8 c7 [2] ac dc [2] a3 c6 [2] bd db [2] bf da [2] a4 dc [2] b8 db [2] a4 f4 }

  condition:
    any of them
}