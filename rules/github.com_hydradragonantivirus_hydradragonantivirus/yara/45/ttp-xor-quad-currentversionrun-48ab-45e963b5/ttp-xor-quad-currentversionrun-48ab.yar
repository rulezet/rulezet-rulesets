rule TTP_XOR_QUAD_CurrentVersionRun_48ab {
  strings:
    $key_48ab = { 1b c4 [2] 3f ca [2] 14 e6 [2] 3a c4 [2] 2e df [2] 21 c5 [2] 3f d8 [2] 3d d9 [2] 26 df [2] 3a d8 [2] 26 f7 }

  condition:
    any of them
}