rule TTP_XOR_MULT_DOSStub_13c6 {
  strings:
    $key_13c6 = { 47 ae [2] 33 b6 [2] 74 b4 [2] 33 a5 [2] 7d a9 [2] 71 a3 [2] 66 a8 [2] 7d e6 [2] 40 }

  condition:
    any of them
}