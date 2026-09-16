rule TTP_XOR_MULT_DOSStub_ab22 {
  strings:
    $key_ab22 = { ff 4a [2] 8b 52 [2] cc 50 [2] 8b 41 [2] c5 4d [2] c9 47 [2] de 4c [2] c5 02 [2] f8 }

  condition:
    any of them
}