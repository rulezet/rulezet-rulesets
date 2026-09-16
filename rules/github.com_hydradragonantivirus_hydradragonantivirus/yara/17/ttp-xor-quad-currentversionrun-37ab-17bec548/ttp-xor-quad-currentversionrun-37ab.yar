rule TTP_XOR_QUAD_CurrentVersionRun_37ab {
  strings:
    $key_37ab = { 64 c4 [2] 40 ca [2] 6b e6 [2] 45 c4 [2] 51 df [2] 5e c5 [2] 40 d8 [2] 42 d9 [2] 59 df [2] 45 d8 [2] 59 f7 }

  condition:
    any of them
}