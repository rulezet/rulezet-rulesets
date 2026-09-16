rule TTP_XOR_MULT_DOSStub_a4cb {
  strings:
    $key_a4cb = { f0 a3 [2] 84 bb [2] c3 b9 [2] 84 a8 [2] ca a4 [2] c6 ae [2] d1 a5 [2] ca eb [2] f7 }

  condition:
    any of them
}