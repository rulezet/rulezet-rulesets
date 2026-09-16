rule TTP_XOR_MULT_DOSStub_ab49 {
  strings:
    $key_ab49 = { ff 21 [2] 8b 39 [2] cc 3b [2] 8b 2a [2] c5 26 [2] c9 2c [2] de 27 [2] c5 69 [2] f8 }

  condition:
    any of them
}