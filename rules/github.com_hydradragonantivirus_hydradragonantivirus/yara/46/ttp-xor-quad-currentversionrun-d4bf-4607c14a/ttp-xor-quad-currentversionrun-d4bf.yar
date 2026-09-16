rule TTP_XOR_QUAD_CurrentVersionRun_d4bf {
  strings:
    $key_d4bf = { 87 d0 [2] a3 de [2] 88 f2 [2] a6 d0 [2] b2 cb [2] bd d1 [2] a3 cc [2] a1 cd [2] ba cb [2] a6 cc [2] ba e3 }

  condition:
    any of them
}