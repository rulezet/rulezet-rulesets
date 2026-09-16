rule TTP_XOR_MULT_DOSStub_abf8 {
  strings:
    $key_abf8 = { ff 90 [2] 8b 88 [2] cc 8a [2] 8b 9b [2] c5 97 [2] c9 9d [2] de 96 [2] c5 d8 [2] f8 }

  condition:
    any of them
}