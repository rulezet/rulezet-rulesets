rule TTP_XOR_MULT_DOSStub_a7cb {
  strings:
    $key_a7cb = { f3 a3 [2] 87 bb [2] c0 b9 [2] 87 a8 [2] c9 a4 [2] c5 ae [2] d2 a5 [2] c9 eb [2] f4 }

  condition:
    any of them
}