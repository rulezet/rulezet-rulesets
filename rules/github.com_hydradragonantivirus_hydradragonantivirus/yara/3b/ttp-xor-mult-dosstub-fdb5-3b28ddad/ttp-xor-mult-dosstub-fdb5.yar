rule TTP_XOR_MULT_DOSStub_fdb5 {
  strings:
    $key_fdb5 = { a9 dd [2] dd c5 [2] 9a c7 [2] dd d6 [2] 93 da [2] 9f d0 [2] 88 db [2] 93 95 [2] ae }

  condition:
    any of them
}