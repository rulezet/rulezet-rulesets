rule TTP_XOR_MULT_DOSStub_ab54 {
  strings:
    $key_ab54 = { ff 3c [2] 8b 24 [2] cc 26 [2] 8b 37 [2] c5 3b [2] c9 31 [2] de 3a [2] c5 74 [2] f8 }

  condition:
    any of them
}