rule TTP_XOR_QUAD_CurrentVersionRun_c3aa {
  strings:
    $key_c3aa = { 90 c5 [2] b4 cb [2] 9f e7 [2] b1 c5 [2] a5 de [2] aa c4 [2] b4 d9 [2] b6 d8 [2] ad de [2] b1 d9 [2] ad f6 }

  condition:
    any of them
}