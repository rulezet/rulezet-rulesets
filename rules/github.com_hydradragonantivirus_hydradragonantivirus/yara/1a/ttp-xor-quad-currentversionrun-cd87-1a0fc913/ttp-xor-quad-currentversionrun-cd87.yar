rule TTP_XOR_QUAD_CurrentVersionRun_cd87 {
  strings:
    $key_cd87 = { 9e e8 [2] ba e6 [2] 91 ca [2] bf e8 [2] ab f3 [2] a4 e9 [2] ba f4 [2] b8 f5 [2] a3 f3 [2] bf f4 [2] a3 db }

  condition:
    any of them
}