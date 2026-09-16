rule TTP_XOR_MULT_DOSStub_ab16 {
  strings:
    $key_ab16 = { ff 7e [2] 8b 66 [2] cc 64 [2] 8b 75 [2] c5 79 [2] c9 73 [2] de 78 [2] c5 36 [2] f8 }

  condition:
    any of them
}