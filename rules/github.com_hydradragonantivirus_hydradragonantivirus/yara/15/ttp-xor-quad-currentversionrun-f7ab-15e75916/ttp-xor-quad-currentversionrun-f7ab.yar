rule TTP_XOR_QUAD_CurrentVersionRun_f7ab {
  strings:
    $key_f7ab = { a4 c4 [2] 80 ca [2] ab e6 [2] 85 c4 [2] 91 df [2] 9e c5 [2] 80 d8 [2] 82 d9 [2] 99 df [2] 85 d8 [2] 99 f7 }

  condition:
    any of them
}