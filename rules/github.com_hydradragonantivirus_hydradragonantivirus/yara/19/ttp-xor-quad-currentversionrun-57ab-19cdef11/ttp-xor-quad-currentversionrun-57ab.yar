rule TTP_XOR_QUAD_CurrentVersionRun_57ab {
  strings:
    $key_57ab = { 04 c4 [2] 20 ca [2] 0b e6 [2] 25 c4 [2] 31 df [2] 3e c5 [2] 20 d8 [2] 22 d9 [2] 39 df [2] 25 d8 [2] 39 f7 }

  condition:
    any of them
}