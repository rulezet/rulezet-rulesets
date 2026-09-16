rule TTP_XOR_MULT_DOSStub_e1cb {
  strings:
    $key_e1cb = { b5 a3 [2] c1 bb [2] 86 b9 [2] c1 a8 [2] 8f a4 [2] 83 ae [2] 94 a5 [2] 8f eb [2] b2 }

  condition:
    any of them
}