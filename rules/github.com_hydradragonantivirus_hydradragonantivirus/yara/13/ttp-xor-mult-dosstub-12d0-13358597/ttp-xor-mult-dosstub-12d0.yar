rule TTP_XOR_MULT_DOSStub_12d0 {
  strings:
    $key_12d0 = { 46 b8 [2] 32 a0 [2] 75 a2 [2] 32 b3 [2] 7c bf [2] 70 b5 [2] 67 be [2] 7c f0 [2] 41 }

  condition:
    any of them
}