rule TTP_XOR_MULT_DOSStub_abf4 {
  strings:
    $key_abf4 = { ff 9c [2] 8b 84 [2] cc 86 [2] 8b 97 [2] c5 9b [2] c9 91 [2] de 9a [2] c5 d4 [2] f8 }

  condition:
    any of them
}