rule TTP_XOR_QUAD_CurrentVersionRun_d2ab {
  strings:
    $key_d2ab = { 81 c4 [2] a5 ca [2] 8e e6 [2] a0 c4 [2] b4 df [2] bb c5 [2] a5 d8 [2] a7 d9 [2] bc df [2] a0 d8 [2] bc f7 }

  condition:
    any of them
}