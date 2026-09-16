rule TTP_XOR_MULT_DOSStub_ab0a {
  strings:
    $key_ab0a = { ff 62 [2] 8b 7a [2] cc 78 [2] 8b 69 [2] c5 65 [2] c9 6f [2] de 64 [2] c5 2a [2] f8 }

  condition:
    any of them
}