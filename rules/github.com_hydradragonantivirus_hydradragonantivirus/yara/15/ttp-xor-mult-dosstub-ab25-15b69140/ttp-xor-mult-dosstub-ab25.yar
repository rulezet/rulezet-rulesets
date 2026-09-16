rule TTP_XOR_MULT_DOSStub_ab25 {
  strings:
    $key_ab25 = { ff 4d [2] 8b 55 [2] cc 57 [2] 8b 46 [2] c5 4a [2] c9 40 [2] de 4b [2] c5 05 [2] f8 }

  condition:
    any of them
}