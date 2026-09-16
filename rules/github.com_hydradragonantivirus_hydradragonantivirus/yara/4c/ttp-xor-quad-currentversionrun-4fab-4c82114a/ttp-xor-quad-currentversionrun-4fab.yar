rule TTP_XOR_QUAD_CurrentVersionRun_4fab {
  strings:
    $key_4fab = { 1c c4 [2] 38 ca [2] 13 e6 [2] 3d c4 [2] 29 df [2] 26 c5 [2] 38 d8 [2] 3a d9 [2] 21 df [2] 3d d8 [2] 21 f7 }

  condition:
    any of them
}