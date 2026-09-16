rule TTP_XOR_MULT_DOSStub_ab4a {
  strings:
    $key_ab4a = { ff 22 [2] 8b 3a [2] cc 38 [2] 8b 29 [2] c5 25 [2] c9 2f [2] de 24 [2] c5 6a [2] f8 }

  condition:
    any of them
}