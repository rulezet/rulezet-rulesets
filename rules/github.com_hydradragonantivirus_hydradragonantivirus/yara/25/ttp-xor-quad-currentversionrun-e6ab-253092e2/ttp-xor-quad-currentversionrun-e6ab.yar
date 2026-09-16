rule TTP_XOR_QUAD_CurrentVersionRun_e6ab {
  strings:
    $key_e6ab = { b5 c4 [2] 91 ca [2] ba e6 [2] 94 c4 [2] 80 df [2] 8f c5 [2] 91 d8 [2] 93 d9 [2] 88 df [2] 94 d8 [2] 88 f7 }

  condition:
    any of them
}