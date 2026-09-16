rule TTP_XOR_MULT_DOSStub_02d0 {
  strings:
    $key_02d0 = { 56 b8 [2] 22 a0 [2] 65 a2 [2] 22 b3 [2] 6c bf [2] 60 b5 [2] 77 be [2] 6c f0 [2] 51 }

  condition:
    any of them
}