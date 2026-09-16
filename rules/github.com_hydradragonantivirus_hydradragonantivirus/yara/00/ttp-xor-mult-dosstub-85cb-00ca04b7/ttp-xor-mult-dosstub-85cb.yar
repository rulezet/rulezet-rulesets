rule TTP_XOR_MULT_DOSStub_85cb {
  strings:
    $key_85cb = { d1 a3 [2] a5 bb [2] e2 b9 [2] a5 a8 [2] eb a4 [2] e7 ae [2] f0 a5 [2] eb eb [2] d6 }

  condition:
    any of them
}