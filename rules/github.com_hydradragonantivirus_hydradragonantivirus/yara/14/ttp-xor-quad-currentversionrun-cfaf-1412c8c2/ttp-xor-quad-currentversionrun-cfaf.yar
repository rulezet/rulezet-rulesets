rule TTP_XOR_QUAD_CurrentVersionRun_cfaf {
  strings:
    $key_cfaf = { 9c c0 [2] b8 ce [2] 93 e2 [2] bd c0 [2] a9 db [2] a6 c1 [2] b8 dc [2] ba dd [2] a1 db [2] bd dc [2] a1 f3 }

  condition:
    any of them
}