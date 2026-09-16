rule TTP_XOR_MULT_DOSStub_ab45 {
  strings:
    $key_ab45 = { ff 2d [2] 8b 35 [2] cc 37 [2] 8b 26 [2] c5 2a [2] c9 20 [2] de 2b [2] c5 65 [2] f8 }

  condition:
    any of them
}