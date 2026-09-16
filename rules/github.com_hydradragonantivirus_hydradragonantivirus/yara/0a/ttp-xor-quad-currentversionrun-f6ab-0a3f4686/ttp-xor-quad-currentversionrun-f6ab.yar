rule TTP_XOR_QUAD_CurrentVersionRun_f6ab {
  strings:
    $key_f6ab = { a5 c4 [2] 81 ca [2] aa e6 [2] 84 c4 [2] 90 df [2] 9f c5 [2] 81 d8 [2] 83 d9 [2] 98 df [2] 84 d8 [2] 98 f7 }

  condition:
    any of them
}