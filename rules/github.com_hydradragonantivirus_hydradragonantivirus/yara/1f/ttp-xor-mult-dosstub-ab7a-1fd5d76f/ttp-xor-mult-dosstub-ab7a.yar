rule TTP_XOR_MULT_DOSStub_ab7a {
  strings:
    $key_ab7a = { ff 12 [2] 8b 0a [2] cc 08 [2] 8b 19 [2] c5 15 [2] c9 1f [2] de 14 [2] c5 5a [2] f8 }

  condition:
    any of them
}