rule TTP_XOR_QUAD_CurrentVersionRun_56ab {
  strings:
    $key_56ab = { 05 c4 [2] 21 ca [2] 0a e6 [2] 24 c4 [2] 30 df [2] 3f c5 [2] 21 d8 [2] 23 d9 [2] 38 df [2] 24 d8 [2] 38 f7 }

  condition:
    any of them
}