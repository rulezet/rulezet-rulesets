rule TTP_XOR_MULT_DOSStub_abe4 {
  strings:
    $key_abe4 = { ff 8c [2] 8b 94 [2] cc 96 [2] 8b 87 [2] c5 8b [2] c9 81 [2] de 8a [2] c5 c4 [2] f8 }

  condition:
    any of them
}