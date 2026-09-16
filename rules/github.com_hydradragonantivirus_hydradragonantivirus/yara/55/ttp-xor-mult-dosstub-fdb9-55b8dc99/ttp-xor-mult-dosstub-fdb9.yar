rule TTP_XOR_MULT_DOSStub_fdb9 {
  strings:
    $key_fdb9 = { a9 d1 [2] dd c9 [2] 9a cb [2] dd da [2] 93 d6 [2] 9f dc [2] 88 d7 [2] 93 99 [2] ae }

  condition:
    any of them
}