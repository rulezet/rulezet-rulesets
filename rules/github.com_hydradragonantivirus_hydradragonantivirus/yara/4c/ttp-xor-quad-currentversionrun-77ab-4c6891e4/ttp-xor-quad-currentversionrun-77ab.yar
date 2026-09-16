rule TTP_XOR_QUAD_CurrentVersionRun_77ab {
  strings:
    $key_77ab = { 24 c4 [2] 00 ca [2] 2b e6 [2] 05 c4 [2] 11 df [2] 1e c5 [2] 00 d8 [2] 02 d9 [2] 19 df [2] 05 d8 [2] 19 f7 }

  condition:
    any of them
}