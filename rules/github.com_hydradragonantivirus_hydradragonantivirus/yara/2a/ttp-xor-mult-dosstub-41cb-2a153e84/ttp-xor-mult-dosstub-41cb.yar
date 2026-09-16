rule TTP_XOR_MULT_DOSStub_41cb {
  strings:
    $key_41cb = { 15 a3 [2] 61 bb [2] 26 b9 [2] 61 a8 [2] 2f a4 [2] 23 ae [2] 34 a5 [2] 2f eb [2] 12 }

  condition:
    any of them
}