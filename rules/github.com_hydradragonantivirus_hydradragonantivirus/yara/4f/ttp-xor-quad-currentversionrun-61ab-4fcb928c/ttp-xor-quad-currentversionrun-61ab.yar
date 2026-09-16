rule TTP_XOR_QUAD_CurrentVersionRun_61ab {
  strings:
    $key_61ab = { 32 c4 [2] 16 ca [2] 3d e6 [2] 13 c4 [2] 07 df [2] 08 c5 [2] 16 d8 [2] 14 d9 [2] 0f df [2] 13 d8 [2] 0f f7 }

  condition:
    any of them
}