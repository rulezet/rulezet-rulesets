rule TTP_XOR_MULT_DOSStub_ab02 {
  strings:
    $key_ab02 = { ff 6a [2] 8b 72 [2] cc 70 [2] 8b 61 [2] c5 6d [2] c9 67 [2] de 6c [2] c5 22 [2] f8 }

  condition:
    any of them
}