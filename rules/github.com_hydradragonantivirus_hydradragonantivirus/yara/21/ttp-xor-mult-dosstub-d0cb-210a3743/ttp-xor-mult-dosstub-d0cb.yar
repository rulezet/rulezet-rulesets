rule TTP_XOR_MULT_DOSStub_d0cb {
  strings:
    $key_d0cb = { 84 a3 [2] f0 bb [2] b7 b9 [2] f0 a8 [2] be a4 [2] b2 ae [2] a5 a5 [2] be eb [2] 83 }

  condition:
    any of them
}