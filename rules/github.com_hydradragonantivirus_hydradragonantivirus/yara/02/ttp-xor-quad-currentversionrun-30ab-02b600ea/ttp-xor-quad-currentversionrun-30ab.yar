rule TTP_XOR_QUAD_CurrentVersionRun_30ab {
  strings:
    $key_30ab = { 63 c4 [2] 47 ca [2] 6c e6 [2] 42 c4 [2] 56 df [2] 59 c5 [2] 47 d8 [2] 45 d9 [2] 5e df [2] 42 d8 [2] 5e f7 }

  condition:
    any of them
}