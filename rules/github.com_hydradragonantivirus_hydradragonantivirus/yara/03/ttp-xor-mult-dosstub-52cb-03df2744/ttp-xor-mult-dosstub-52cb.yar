rule TTP_XOR_MULT_DOSStub_52cb {
  strings:
    $key_52cb = { 06 a3 [2] 72 bb [2] 35 b9 [2] 72 a8 [2] 3c a4 [2] 30 ae [2] 27 a5 [2] 3c eb [2] 01 }

  condition:
    any of them
}