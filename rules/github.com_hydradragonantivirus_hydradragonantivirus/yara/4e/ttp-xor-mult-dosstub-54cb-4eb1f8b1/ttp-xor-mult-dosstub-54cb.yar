rule TTP_XOR_MULT_DOSStub_54cb {
  strings:
    $key_54cb = { 00 a3 [2] 74 bb [2] 33 b9 [2] 74 a8 [2] 3a a4 [2] 36 ae [2] 21 a5 [2] 3a eb [2] 07 }

  condition:
    any of them
}