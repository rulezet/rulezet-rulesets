rule TTP_XOR_MULT_DOSStub_abf9 {
  strings:
    $key_abf9 = { ff 91 [2] 8b 89 [2] cc 8b [2] 8b 9a [2] c5 96 [2] c9 9c [2] de 97 [2] c5 d9 [2] f8 }

  condition:
    any of them
}