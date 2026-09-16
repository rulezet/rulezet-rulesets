rule TTP_XOR_MULT_DOSStub_ab73 {
  strings:
    $key_ab73 = { ff 1b [2] 8b 03 [2] cc 01 [2] 8b 10 [2] c5 1c [2] c9 16 [2] de 1d [2] c5 53 [2] f8 }

  condition:
    any of them
}