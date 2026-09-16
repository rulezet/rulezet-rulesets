rule TTP_XOR_QUAD_CurrentVersionRun_cfa6 {
  strings:
    $key_cfa6 = { 9c c9 [2] b8 c7 [2] 93 eb [2] bd c9 [2] a9 d2 [2] a6 c8 [2] b8 d5 [2] ba d4 [2] a1 d2 [2] bd d5 [2] a1 fa }

  condition:
    any of them
}