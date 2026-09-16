rule TTP_XOR_QUAD_CurrentVersionRun_caa2 {
  strings:
    $key_caa2 = { 99 cd [2] bd c3 [2] 96 ef [2] b8 cd [2] ac d6 [2] a3 cc [2] bd d1 [2] bf d0 [2] a4 d6 [2] b8 d1 [2] a4 fe }

  condition:
    any of them
}