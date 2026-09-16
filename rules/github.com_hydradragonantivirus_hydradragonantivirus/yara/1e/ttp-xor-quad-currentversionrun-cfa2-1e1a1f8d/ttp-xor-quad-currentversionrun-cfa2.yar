rule TTP_XOR_QUAD_CurrentVersionRun_cfa2 {
  strings:
    $key_cfa2 = { 9c cd [2] b8 c3 [2] 93 ef [2] bd cd [2] a9 d6 [2] a6 cc [2] b8 d1 [2] ba d0 [2] a1 d6 [2] bd d1 [2] a1 fe }

  condition:
    any of them
}