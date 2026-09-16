rule TTP_XOR_QUAD_CurrentVersionRun_1fab {
  strings:
    $key_1fab = { 4c c4 [2] 68 ca [2] 43 e6 [2] 6d c4 [2] 79 df [2] 76 c5 [2] 68 d8 [2] 6a d9 [2] 71 df [2] 6d d8 [2] 71 f7 }

  condition:
    any of them
}