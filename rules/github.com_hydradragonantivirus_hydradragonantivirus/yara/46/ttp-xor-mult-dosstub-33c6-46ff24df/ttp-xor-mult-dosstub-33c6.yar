rule TTP_XOR_MULT_DOSStub_33c6 {
  strings:
    $key_33c6 = { 67 ae [2] 13 b6 [2] 54 b4 [2] 13 a5 [2] 5d a9 [2] 51 a3 [2] 46 a8 [2] 5d e6 [2] 60 }

  condition:
    any of them
}