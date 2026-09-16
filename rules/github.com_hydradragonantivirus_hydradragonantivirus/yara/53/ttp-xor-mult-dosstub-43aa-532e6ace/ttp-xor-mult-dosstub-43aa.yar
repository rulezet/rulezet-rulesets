rule TTP_XOR_MULT_DOSStub_43aa {
  strings:
    $key_43aa = { 17 c2 [2] 63 da [2] 24 d8 [2] 63 c9 [2] 2d c5 [2] 21 cf [2] 36 c4 [2] 2d 8a [2] 10 }

  condition:
    any of them
}