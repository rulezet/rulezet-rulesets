rule TTP_XOR_MULT_DOSStub_ab76 {
  strings:
    $key_ab76 = { ff 1e [2] 8b 06 [2] cc 04 [2] 8b 15 [2] c5 19 [2] c9 13 [2] de 18 [2] c5 56 [2] f8 }

  condition:
    any of them
}