rule TTP_XOR_QUAD_CurrentVersionRun_d8b8 {
  strings:
    $key_d8b8 = { 8b d7 [2] af d9 [2] 84 f5 [2] aa d7 [2] be cc [2] b1 d6 [2] af cb [2] ad ca [2] b6 cc [2] aa cb [2] b6 e4 }

  condition:
    any of them
}