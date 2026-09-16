rule TTP_XOR_MULT_DOSStub_ab1f {
  strings:
    $key_ab1f = { ff 77 [2] 8b 6f [2] cc 6d [2] 8b 7c [2] c5 70 [2] c9 7a [2] de 71 [2] c5 3f [2] f8 }

  condition:
    any of them
}