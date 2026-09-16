rule TTP_XOR_MULT_DOSStub_ab18 {
  strings:
    $key_ab18 = { ff 70 [2] 8b 68 [2] cc 6a [2] 8b 7b [2] c5 77 [2] c9 7d [2] de 76 [2] c5 38 [2] f8 }

  condition:
    any of them
}