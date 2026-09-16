rule TTP_XOR_QUAD_CurrentVersionRun_f887 {
  strings:
    $key_f887 = { ab e8 [2] 8f e6 [2] a4 ca [2] 8a e8 [2] 9e f3 [2] 91 e9 [2] 8f f4 [2] 8d f5 [2] 96 f3 [2] 8a f4 [2] 96 db }

  condition:
    any of them
}