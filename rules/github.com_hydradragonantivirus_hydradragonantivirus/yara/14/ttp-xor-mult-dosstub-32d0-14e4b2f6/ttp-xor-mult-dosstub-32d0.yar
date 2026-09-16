rule TTP_XOR_MULT_DOSStub_32d0 {
  strings:
    $key_32d0 = { 66 b8 [2] 12 a0 [2] 55 a2 [2] 12 b3 [2] 5c bf [2] 50 b5 [2] 47 be [2] 5c f0 [2] 61 }

  condition:
    any of them
}