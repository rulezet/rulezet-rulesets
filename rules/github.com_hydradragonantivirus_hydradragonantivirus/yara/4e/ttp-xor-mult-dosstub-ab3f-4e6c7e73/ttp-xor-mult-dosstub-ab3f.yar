rule TTP_XOR_MULT_DOSStub_ab3f {
  strings:
    $key_ab3f = { ff 57 [2] 8b 4f [2] cc 4d [2] 8b 5c [2] c5 50 [2] c9 5a [2] de 51 [2] c5 1f [2] f8 }

  condition:
    any of them
}