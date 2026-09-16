rule TTP_XOR_QUAD_CurrentVersionRun_c2aa {
  strings:
    $key_c2aa = { 91 c5 [2] b5 cb [2] 9e e7 [2] b0 c5 [2] a4 de [2] ab c4 [2] b5 d9 [2] b7 d8 [2] ac de [2] b0 d9 [2] ac f6 }

  condition:
    any of them
}