rule TTP_XOR_MULT_DOSStub_ab72 {
  strings:
    $key_ab72 = { ff 1a [2] 8b 02 [2] cc 00 [2] 8b 11 [2] c5 1d [2] c9 17 [2] de 1c [2] c5 52 [2] f8 }

  condition:
    any of them
}