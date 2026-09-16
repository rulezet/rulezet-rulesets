rule TTP_XOR_QUAD_CurrentVersionRun_e4ab {
  strings:
    $key_e4ab = { b7 c4 [2] 93 ca [2] b8 e6 [2] 96 c4 [2] 82 df [2] 8d c5 [2] 93 d8 [2] 91 d9 [2] 8a df [2] 96 d8 [2] 8a f7 }

  condition:
    any of them
}