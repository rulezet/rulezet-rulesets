rule TTP_XOR_QUAD_CurrentVersionRun_caba {
  strings:
    $key_caba = { 99 d5 [2] bd db [2] 96 f7 [2] b8 d5 [2] ac ce [2] a3 d4 [2] bd c9 [2] bf c8 [2] a4 ce [2] b8 c9 [2] a4 e6 }

  condition:
    any of them
}