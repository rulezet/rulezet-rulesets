rule TTP_XOR_MULT_DOSStub_40c6 {
  strings:
    $key_40c6 = { 14 ae [2] 60 b6 [2] 27 b4 [2] 60 a5 [2] 2e a9 [2] 22 a3 [2] 35 a8 [2] 2e e6 [2] 13 }

  condition:
    any of them
}