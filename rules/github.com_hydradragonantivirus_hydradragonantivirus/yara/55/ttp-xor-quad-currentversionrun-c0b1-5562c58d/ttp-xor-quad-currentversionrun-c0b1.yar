rule TTP_XOR_QUAD_CurrentVersionRun_c0b1 {
  strings:
    $key_c0b1 = { 93 de [2] b7 d0 [2] 9c fc [2] b2 de [2] a6 c5 [2] a9 df [2] b7 c2 [2] b5 c3 [2] ae c5 [2] b2 c2 [2] ae ed }

  condition:
    any of them
}