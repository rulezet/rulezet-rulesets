rule TTP_XOR_MULT_DOSStub_48b0 {
  strings:
    $key_48b0 = { 1c d8 [2] 68 c0 [2] 2f c2 [2] 68 d3 [2] 26 df [2] 2a d5 [2] 3d de [2] 26 90 [2] 1b }

  condition:
    any of them
}