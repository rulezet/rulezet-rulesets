rule TTP_XOR_MULT_DOSStub_ab68 {
  strings:
    $key_ab68 = { ff 00 [2] 8b 18 [2] cc 1a [2] 8b 0b [2] c5 07 [2] c9 0d [2] de 06 [2] c5 48 [2] f8 }

  condition:
    any of them
}