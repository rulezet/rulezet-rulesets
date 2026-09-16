rule TTP_XOR_MULT_DOSStub_33cb {
  strings:
    $key_33cb = { 67 a3 [2] 13 bb [2] 54 b9 [2] 13 a8 [2] 5d a4 [2] 51 ae [2] 46 a5 [2] 5d eb [2] 60 }

  condition:
    any of them
}