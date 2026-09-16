rule TTP_XOR_QUAD_CurrentVersionRun_04ab {
  strings:
    $key_04ab = { 57 c4 [2] 73 ca [2] 58 e6 [2] 76 c4 [2] 62 df [2] 6d c5 [2] 73 d8 [2] 71 d9 [2] 6a df [2] 76 d8 [2] 6a f7 }

  condition:
    any of them
}