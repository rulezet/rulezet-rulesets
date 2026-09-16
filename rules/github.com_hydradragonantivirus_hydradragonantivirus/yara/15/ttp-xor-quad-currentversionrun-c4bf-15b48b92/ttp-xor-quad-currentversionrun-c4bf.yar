rule TTP_XOR_QUAD_CurrentVersionRun_c4bf {
  strings:
    $key_c4bf = { 97 d0 [2] b3 de [2] 98 f2 [2] b6 d0 [2] a2 cb [2] ad d1 [2] b3 cc [2] b1 cd [2] aa cb [2] b6 cc [2] aa e3 }

  condition:
    any of them
}