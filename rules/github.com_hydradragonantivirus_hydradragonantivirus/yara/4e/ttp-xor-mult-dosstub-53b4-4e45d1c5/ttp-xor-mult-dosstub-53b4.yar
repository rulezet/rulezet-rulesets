rule TTP_XOR_MULT_DOSStub_53b4 {
  strings:
    $key_53b4 = { 07 dc [2] 73 c4 [2] 34 c6 [2] 73 d7 [2] 3d db [2] 31 d1 [2] 26 da [2] 3d 94 [2] 00 }

  condition:
    any of them
}