rule TTP_XOR_MULT_DOSStub_ab15 {
  strings:
    $key_ab15 = { ff 7d [2] 8b 65 [2] cc 67 [2] 8b 76 [2] c5 7a [2] c9 70 [2] de 7b [2] c5 35 [2] f8 }

  condition:
    any of them
}