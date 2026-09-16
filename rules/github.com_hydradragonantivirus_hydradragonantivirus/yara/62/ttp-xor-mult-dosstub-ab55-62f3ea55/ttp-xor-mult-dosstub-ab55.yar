rule TTP_XOR_MULT_DOSStub_ab55 {
  strings:
    $key_ab55 = { ff 3d [2] 8b 25 [2] cc 27 [2] 8b 36 [2] c5 3a [2] c9 30 [2] de 3b [2] c5 75 [2] f8 }

  condition:
    any of them
}