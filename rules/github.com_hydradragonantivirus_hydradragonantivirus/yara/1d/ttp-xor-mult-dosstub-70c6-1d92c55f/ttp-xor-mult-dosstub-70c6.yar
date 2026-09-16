rule TTP_XOR_MULT_DOSStub_70c6 {
  strings:
    $key_70c6 = { 24 ae [2] 50 b6 [2] 17 b4 [2] 50 a5 [2] 1e a9 [2] 12 a3 [2] 05 a8 [2] 1e e6 [2] 23 }

  condition:
    any of them
}