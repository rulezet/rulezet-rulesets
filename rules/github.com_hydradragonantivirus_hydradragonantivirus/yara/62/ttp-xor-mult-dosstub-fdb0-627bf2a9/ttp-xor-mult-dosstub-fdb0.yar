rule TTP_XOR_MULT_DOSStub_fdb0 {
  strings:
    $key_fdb0 = { a9 d8 [2] dd c0 [2] 9a c2 [2] dd d3 [2] 93 df [2] 9f d5 [2] 88 de [2] 93 90 [2] ae }

  condition:
    any of them
}