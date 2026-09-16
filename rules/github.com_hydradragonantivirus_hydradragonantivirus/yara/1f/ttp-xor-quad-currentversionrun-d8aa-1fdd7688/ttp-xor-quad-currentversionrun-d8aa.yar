rule TTP_XOR_QUAD_CurrentVersionRun_d8aa {
  strings:
    $key_d8aa = { 8b c5 [2] af cb [2] 84 e7 [2] aa c5 [2] be de [2] b1 c4 [2] af d9 [2] ad d8 [2] b6 de [2] aa d9 [2] b6 f6 }

  condition:
    any of them
}