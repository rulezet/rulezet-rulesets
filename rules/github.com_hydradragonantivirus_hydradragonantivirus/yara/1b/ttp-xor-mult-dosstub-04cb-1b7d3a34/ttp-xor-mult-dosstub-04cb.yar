rule TTP_XOR_MULT_DOSStub_04cb {
  strings:
    $key_04cb = { 50 a3 [2] 24 bb [2] 63 b9 [2] 24 a8 [2] 6a a4 [2] 66 ae [2] 71 a5 [2] 6a eb [2] 57 }

  condition:
    any of them
}