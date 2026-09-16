rule TTP_XOR_MULT_DOSStub_ab2d {
  strings:
    $key_ab2d = { ff 45 [2] 8b 5d [2] cc 5f [2] 8b 4e [2] c5 42 [2] c9 48 [2] de 43 [2] c5 0d [2] f8 }

  condition:
    any of them
}