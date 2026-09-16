rule TTP_XOR_MULT_DOSStub_52d0 {
  strings:
    $key_52d0 = { 06 b8 [2] 72 a0 [2] 35 a2 [2] 72 b3 [2] 3c bf [2] 30 b5 [2] 27 be [2] 3c f0 [2] 01 }

  condition:
    any of them
}