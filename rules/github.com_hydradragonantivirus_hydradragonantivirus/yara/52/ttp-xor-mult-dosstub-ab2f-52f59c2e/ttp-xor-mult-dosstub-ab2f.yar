rule TTP_XOR_MULT_DOSStub_ab2f {
  strings:
    $key_ab2f = { ff 47 [2] 8b 5f [2] cc 5d [2] 8b 4c [2] c5 40 [2] c9 4a [2] de 41 [2] c5 0f [2] f8 }

  condition:
    any of them
}