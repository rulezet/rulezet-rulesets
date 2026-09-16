rule TTP_XOR_MULT_DOSStub_ab0f {
  strings:
    $key_ab0f = { ff 67 [2] 8b 7f [2] cc 7d [2] 8b 6c [2] c5 60 [2] c9 6a [2] de 61 [2] c5 2f [2] f8 }

  condition:
    any of them
}