rule TTP_XOR_QUAD_CurrentVersionRun_c7bf {
  strings:
    $key_c7bf = { 94 d0 [2] b0 de [2] 9b f2 [2] b5 d0 [2] a1 cb [2] ae d1 [2] b0 cc [2] b2 cd [2] a9 cb [2] b5 cc [2] a9 e3 }

  condition:
    any of them
}