rule TTP_XOR_MULT_DOSStub_ab7d {
  strings:
    $key_ab7d = { ff 15 [2] 8b 0d [2] cc 0f [2] 8b 1e [2] c5 12 [2] c9 18 [2] de 13 [2] c5 5d [2] f8 }

  condition:
    any of them
}