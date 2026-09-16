rule TTP_XOR_MULT_DOSStub_43cb {
  strings:
    $key_43cb = { 17 a3 [2] 63 bb [2] 24 b9 [2] 63 a8 [2] 2d a4 [2] 21 ae [2] 36 a5 [2] 2d eb [2] 10 }

  condition:
    any of them
}