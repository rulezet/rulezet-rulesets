rule TTP_XOR_QUAD_CurrentVersionRun_d3aa {
  strings:
    $key_d3aa = { 80 c5 [2] a4 cb [2] 8f e7 [2] a1 c5 [2] b5 de [2] ba c4 [2] a4 d9 [2] a6 d8 [2] bd de [2] a1 d9 [2] bd f6 }

  condition:
    any of them
}