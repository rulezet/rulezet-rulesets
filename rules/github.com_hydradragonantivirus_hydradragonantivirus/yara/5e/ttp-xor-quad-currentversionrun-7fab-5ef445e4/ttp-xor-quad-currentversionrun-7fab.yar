rule TTP_XOR_QUAD_CurrentVersionRun_7fab {
  strings:
    $key_7fab = { 2c c4 [2] 08 ca [2] 23 e6 [2] 0d c4 [2] 19 df [2] 16 c5 [2] 08 d8 [2] 0a d9 [2] 11 df [2] 0d d8 [2] 11 f7 }

  condition:
    any of them
}