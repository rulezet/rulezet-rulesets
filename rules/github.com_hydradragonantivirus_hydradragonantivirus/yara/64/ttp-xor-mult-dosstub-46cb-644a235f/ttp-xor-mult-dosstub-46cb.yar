rule TTP_XOR_MULT_DOSStub_46cb {
  strings:
    $key_46cb = { 12 a3 [2] 66 bb [2] 21 b9 [2] 66 a8 [2] 28 a4 [2] 24 ae [2] 33 a5 [2] 28 eb [2] 15 }

  condition:
    any of them
}