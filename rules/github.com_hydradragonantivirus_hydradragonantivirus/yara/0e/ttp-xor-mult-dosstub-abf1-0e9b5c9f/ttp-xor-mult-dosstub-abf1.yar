rule TTP_XOR_MULT_DOSStub_abf1 {
  strings:
    $key_abf1 = { ff 99 [2] 8b 81 [2] cc 83 [2] 8b 92 [2] c5 9e [2] c9 94 [2] de 9f [2] c5 d1 [2] f8 }

  condition:
    any of them
}