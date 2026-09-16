rule TTP_XOR_QUAD_CurrentVersionRun_f0ab {
  strings:
    $key_f0ab = { a3 c4 [2] 87 ca [2] ac e6 [2] 82 c4 [2] 96 df [2] 99 c5 [2] 87 d8 [2] 85 d9 [2] 9e df [2] 82 d8 [2] 9e f7 }

  condition:
    any of them
}