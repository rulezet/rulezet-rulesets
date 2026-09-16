rule TTP_XOR_QUAD_CurrentVersionRun_caaf {
  strings:
    $key_caaf = { 99 c0 [2] bd ce [2] 96 e2 [2] b8 c0 [2] ac db [2] a3 c1 [2] bd dc [2] bf dd [2] a4 db [2] b8 dc [2] a4 f3 }

  condition:
    any of them
}