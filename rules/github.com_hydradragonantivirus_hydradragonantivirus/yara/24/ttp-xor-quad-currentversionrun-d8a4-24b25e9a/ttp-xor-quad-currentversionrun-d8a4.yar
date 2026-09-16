rule TTP_XOR_QUAD_CurrentVersionRun_d8a4 {
  strings:
    $key_d8a4 = { 8b cb [2] af c5 [2] 84 e9 [2] aa cb [2] be d0 [2] b1 ca [2] af d7 [2] ad d6 [2] b6 d0 [2] aa d7 [2] b6 f8 }

  condition:
    any of them
}