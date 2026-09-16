rule TTP_XOR_QUAD_CurrentVersionRun_53ab {
  strings:
    $key_53ab = { 00 c4 [2] 24 ca [2] 0f e6 [2] 21 c4 [2] 35 df [2] 3a c5 [2] 24 d8 [2] 26 d9 [2] 3d df [2] 21 d8 [2] 3d f7 }

  condition:
    any of them
}