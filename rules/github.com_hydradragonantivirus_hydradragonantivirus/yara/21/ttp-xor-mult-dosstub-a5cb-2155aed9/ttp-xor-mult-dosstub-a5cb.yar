rule TTP_XOR_MULT_DOSStub_a5cb {
  strings:
    $key_a5cb = { f1 a3 [2] 85 bb [2] c2 b9 [2] 85 a8 [2] cb a4 [2] c7 ae [2] d0 a5 [2] cb eb [2] f6 }

  condition:
    any of them
}