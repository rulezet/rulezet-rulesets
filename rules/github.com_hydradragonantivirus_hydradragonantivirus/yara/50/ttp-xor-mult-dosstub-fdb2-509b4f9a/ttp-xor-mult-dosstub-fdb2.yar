rule TTP_XOR_MULT_DOSStub_fdb2 {
  strings:
    $key_fdb2 = { a9 da [2] dd c2 [2] 9a c0 [2] dd d1 [2] 93 dd [2] 9f d7 [2] 88 dc [2] 93 92 [2] ae }

  condition:
    any of them
}