rule TTP_XOR_MULT_DOSStub_ab24 {
  strings:
    $key_ab24 = { ff 4c [2] 8b 54 [2] cc 56 [2] 8b 47 [2] c5 4b [2] c9 41 [2] de 4a [2] c5 04 [2] f8 }

  condition:
    any of them
}