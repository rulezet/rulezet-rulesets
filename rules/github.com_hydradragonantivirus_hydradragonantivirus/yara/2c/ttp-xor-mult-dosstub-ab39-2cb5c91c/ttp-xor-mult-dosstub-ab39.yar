rule TTP_XOR_MULT_DOSStub_ab39 {
  strings:
    $key_ab39 = { ff 51 [2] 8b 49 [2] cc 4b [2] 8b 5a [2] c5 56 [2] c9 5c [2] de 57 [2] c5 19 [2] f8 }

  condition:
    any of them
}