rule TTP_XOR_MULT_DOSStub_60cb {
  strings:
    $key_60cb = { 34 a3 [2] 40 bb [2] 07 b9 [2] 40 a8 [2] 0e a4 [2] 02 ae [2] 15 a5 [2] 0e eb [2] 33 }

  condition:
    any of them
}