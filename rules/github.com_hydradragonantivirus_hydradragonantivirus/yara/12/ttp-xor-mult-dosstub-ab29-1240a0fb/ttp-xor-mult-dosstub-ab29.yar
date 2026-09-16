rule TTP_XOR_MULT_DOSStub_ab29 {
  strings:
    $key_ab29 = { ff 41 [2] 8b 59 [2] cc 5b [2] 8b 4a [2] c5 46 [2] c9 4c [2] de 47 [2] c5 09 [2] f8 }

  condition:
    any of them
}