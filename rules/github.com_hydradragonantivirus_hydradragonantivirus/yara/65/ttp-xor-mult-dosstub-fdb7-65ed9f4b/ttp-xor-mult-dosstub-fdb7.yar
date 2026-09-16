rule TTP_XOR_MULT_DOSStub_fdb7 {
  strings:
    $key_fdb7 = { a9 df [2] dd c7 [2] 9a c5 [2] dd d4 [2] 93 d8 [2] 9f d2 [2] 88 d9 [2] 93 97 [2] ae }

  condition:
    any of them
}