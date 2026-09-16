rule TTP_XOR_MULT_DOSStub_ab23 {
  strings:
    $key_ab23 = { ff 4b [2] 8b 53 [2] cc 51 [2] 8b 40 [2] c5 4c [2] c9 46 [2] de 4d [2] c5 03 [2] f8 }

  condition:
    any of them
}