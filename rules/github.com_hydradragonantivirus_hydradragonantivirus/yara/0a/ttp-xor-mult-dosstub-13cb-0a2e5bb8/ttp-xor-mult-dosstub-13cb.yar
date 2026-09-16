rule TTP_XOR_MULT_DOSStub_13cb {
  strings:
    $key_13cb = { 47 a3 [2] 33 bb [2] 74 b9 [2] 33 a8 [2] 7d a4 [2] 71 ae [2] 66 a5 [2] 7d eb [2] 40 }

  condition:
    any of them
}