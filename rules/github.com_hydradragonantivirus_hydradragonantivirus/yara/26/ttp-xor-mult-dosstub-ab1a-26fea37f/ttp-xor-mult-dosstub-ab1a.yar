rule TTP_XOR_MULT_DOSStub_ab1a {
  strings:
    $key_ab1a = { ff 72 [2] 8b 6a [2] cc 68 [2] 8b 79 [2] c5 75 [2] c9 7f [2] de 74 [2] c5 3a [2] f8 }

  condition:
    any of them
}