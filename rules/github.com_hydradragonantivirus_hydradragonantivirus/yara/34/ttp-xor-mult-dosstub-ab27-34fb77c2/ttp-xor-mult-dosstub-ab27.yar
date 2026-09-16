rule TTP_XOR_MULT_DOSStub_ab27 {
  strings:
    $key_ab27 = { ff 4f [2] 8b 57 [2] cc 55 [2] 8b 44 [2] c5 48 [2] c9 42 [2] de 49 [2] c5 07 [2] f8 }

  condition:
    any of them
}