rule TTP_XOR_QUAD_CurrentVersionRun_14ab {
  strings:
    $key_14ab = { 47 c4 [2] 63 ca [2] 48 e6 [2] 66 c4 [2] 72 df [2] 7d c5 [2] 63 d8 [2] 61 d9 [2] 7a df [2] 66 d8 [2] 7a f7 }

  condition:
    any of them
}