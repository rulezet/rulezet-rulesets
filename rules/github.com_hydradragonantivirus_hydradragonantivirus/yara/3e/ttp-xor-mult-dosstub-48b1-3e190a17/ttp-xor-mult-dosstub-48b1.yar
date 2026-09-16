rule TTP_XOR_MULT_DOSStub_48b1 {
  strings:
    $key_48b1 = { 1c d9 [2] 68 c1 [2] 2f c3 [2] 68 d2 [2] 26 de [2] 2a d4 [2] 3d df [2] 26 91 [2] 1b }

  condition:
    any of them
}