rule TTP_XOR_MULT_DOSStub_ab14 {
  strings:
    $key_ab14 = { ff 7c [2] 8b 64 [2] cc 66 [2] 8b 77 [2] c5 7b [2] c9 71 [2] de 7a [2] c5 34 [2] f8 }

  condition:
    any of them
}