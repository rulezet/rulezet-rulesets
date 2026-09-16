rule TTP_XOR_MULT_DOSStub_ab20 {
  strings:
    $key_ab20 = { ff 48 [2] 8b 50 [2] cc 52 [2] 8b 43 [2] c5 4f [2] c9 45 [2] de 4e [2] c5 00 [2] f8 }

  condition:
    any of them
}