rule TTP_XOR_QUAD_CurrentVersionRun_10ab {
  strings:
    $key_10ab = { 43 c4 [2] 67 ca [2] 4c e6 [2] 62 c4 [2] 76 df [2] 79 c5 [2] 67 d8 [2] 65 d9 [2] 7e df [2] 62 d8 [2] 7e f7 }

  condition:
    any of them
}