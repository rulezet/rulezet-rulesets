rule TTP_XOR_MULT_DOSStub_ab10 {
  strings:
    $key_ab10 = { ff 78 [2] 8b 60 [2] cc 62 [2] 8b 73 [2] c5 7f [2] c9 75 [2] de 7e [2] c5 30 [2] f8 }

  condition:
    any of them
}