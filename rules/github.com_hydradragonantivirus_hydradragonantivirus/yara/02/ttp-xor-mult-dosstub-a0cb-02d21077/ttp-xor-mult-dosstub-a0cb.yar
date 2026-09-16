rule TTP_XOR_MULT_DOSStub_a0cb {
  strings:
    $key_a0cb = { f4 a3 [2] 80 bb [2] c7 b9 [2] 80 a8 [2] ce a4 [2] c2 ae [2] d5 a5 [2] ce eb [2] f3 }

  condition:
    any of them
}