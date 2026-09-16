rule TTP_XOR_MULT_DOSStub_01cb {
  strings:
    $key_01cb = { 55 a3 [2] 21 bb [2] 66 b9 [2] 21 a8 [2] 6f a4 [2] 63 ae [2] 74 a5 [2] 6f eb [2] 52 }

  condition:
    any of them
}