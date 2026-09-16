rule TTP_XOR_QUAD_CurrentVersionRun_cfdb {
  strings:
    $key_cfdb = { 9c b4 [2] b8 ba [2] 93 96 [2] bd b4 [2] a9 af [2] a6 b5 [2] b8 a8 [2] ba a9 [2] a1 af [2] bd a8 [2] a1 87 }

  condition:
    any of them
}