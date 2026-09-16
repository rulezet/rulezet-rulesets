rule TTP_XOR_MULT_DOSStub_ab3a {
  strings:
    $key_ab3a = { ff 52 [2] 8b 4a [2] cc 48 [2] 8b 59 [2] c5 55 [2] c9 5f [2] de 54 [2] c5 1a [2] f8 }

  condition:
    any of them
}