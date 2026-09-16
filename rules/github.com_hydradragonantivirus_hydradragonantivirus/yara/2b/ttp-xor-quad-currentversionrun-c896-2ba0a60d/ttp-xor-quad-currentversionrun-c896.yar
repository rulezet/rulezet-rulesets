rule TTP_XOR_QUAD_CurrentVersionRun_c896 {
  strings:
    $key_c896 = { 9b f9 [2] bf f7 [2] 94 db [2] ba f9 [2] ae e2 [2] a1 f8 [2] bf e5 [2] bd e4 [2] a6 e2 [2] ba e5 [2] a6 ca }

  condition:
    any of them
}