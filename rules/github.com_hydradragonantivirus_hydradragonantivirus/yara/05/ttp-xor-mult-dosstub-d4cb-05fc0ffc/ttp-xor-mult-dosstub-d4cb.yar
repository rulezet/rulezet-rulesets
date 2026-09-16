rule TTP_XOR_MULT_DOSStub_d4cb {
  strings:
    $key_d4cb = { 80 a3 [2] f4 bb [2] b3 b9 [2] f4 a8 [2] ba a4 [2] b6 ae [2] a1 a5 [2] ba eb [2] 87 }

  condition:
    any of them
}