rule TTP_XOR_QUAD_CurrentVersionRun_27ab {
  strings:
    $key_27ab = { 74 c4 [2] 50 ca [2] 7b e6 [2] 55 c4 [2] 41 df [2] 4e c5 [2] 50 d8 [2] 52 d9 [2] 49 df [2] 55 d8 [2] 49 f7 }

  condition:
    any of them
}