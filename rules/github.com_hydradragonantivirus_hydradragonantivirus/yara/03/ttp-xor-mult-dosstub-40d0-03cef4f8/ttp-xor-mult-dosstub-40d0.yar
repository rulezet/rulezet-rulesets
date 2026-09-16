rule TTP_XOR_MULT_DOSStub_40d0 {
  strings:
    $key_40d0 = { 14 b8 [2] 60 a0 [2] 27 a2 [2] 60 b3 [2] 2e bf [2] 22 b5 [2] 35 be [2] 2e f0 [2] 13 }

  condition:
    any of them
}