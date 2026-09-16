rule TTP_XOR_MULT_DOSStub_63c6 {
  strings:
    $key_63c6 = { 37 ae [2] 43 b6 [2] 04 b4 [2] 43 a5 [2] 0d a9 [2] 01 a3 [2] 16 a8 [2] 0d e6 [2] 30 }

  condition:
    any of them
}