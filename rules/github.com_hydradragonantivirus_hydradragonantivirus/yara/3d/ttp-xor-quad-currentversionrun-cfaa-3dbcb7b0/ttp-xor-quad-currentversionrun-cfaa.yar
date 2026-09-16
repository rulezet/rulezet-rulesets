rule TTP_XOR_QUAD_CurrentVersionRun_cfaa {
  strings:
    $key_cfaa = { 9c c5 [2] b8 cb [2] 93 e7 [2] bd c5 [2] a9 de [2] a6 c4 [2] b8 d9 [2] ba d8 [2] a1 de [2] bd d9 [2] a1 f6 }

  condition:
    any of them
}