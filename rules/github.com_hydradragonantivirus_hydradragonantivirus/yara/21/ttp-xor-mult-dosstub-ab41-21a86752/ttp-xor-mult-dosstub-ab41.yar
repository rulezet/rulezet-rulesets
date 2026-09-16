rule TTP_XOR_MULT_DOSStub_ab41 {
  strings:
    $key_ab41 = { ff 29 [2] 8b 31 [2] cc 33 [2] 8b 22 [2] c5 2e [2] c9 24 [2] de 2f [2] c5 61 [2] f8 }

  condition:
    any of them
}