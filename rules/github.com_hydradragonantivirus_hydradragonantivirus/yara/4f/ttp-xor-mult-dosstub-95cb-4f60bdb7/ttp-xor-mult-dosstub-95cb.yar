rule TTP_XOR_MULT_DOSStub_95cb {
  strings:
    $key_95cb = { c1 a3 [2] b5 bb [2] f2 b9 [2] b5 a8 [2] fb a4 [2] f7 ae [2] e0 a5 [2] fb eb [2] c6 }

  condition:
    any of them
}