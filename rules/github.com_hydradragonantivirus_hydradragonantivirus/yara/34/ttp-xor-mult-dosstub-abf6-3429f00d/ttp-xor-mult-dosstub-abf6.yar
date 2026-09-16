rule TTP_XOR_MULT_DOSStub_abf6 {
  strings:
    $key_abf6 = { ff 9e [2] 8b 86 [2] cc 84 [2] 8b 95 [2] c5 99 [2] c9 93 [2] de 98 [2] c5 d6 [2] f8 }

  condition:
    any of them
}