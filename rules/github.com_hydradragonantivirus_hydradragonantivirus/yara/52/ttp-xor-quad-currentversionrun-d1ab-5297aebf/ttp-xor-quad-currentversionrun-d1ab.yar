rule TTP_XOR_QUAD_CurrentVersionRun_d1ab {
  strings:
    $key_d1ab = { 82 c4 [2] a6 ca [2] 8d e6 [2] a3 c4 [2] b7 df [2] b8 c5 [2] a6 d8 [2] a4 d9 [2] bf df [2] a3 d8 [2] bf f7 }

  condition:
    any of them
}