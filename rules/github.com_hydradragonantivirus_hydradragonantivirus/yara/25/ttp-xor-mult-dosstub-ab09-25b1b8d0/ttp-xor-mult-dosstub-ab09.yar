rule TTP_XOR_MULT_DOSStub_ab09 {
  strings:
    $key_ab09 = { ff 61 [2] 8b 79 [2] cc 7b [2] 8b 6a [2] c5 66 [2] c9 6c [2] de 67 [2] c5 29 [2] f8 }

  condition:
    any of them
}