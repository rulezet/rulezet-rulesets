rule TTP_XOR_MULT_DOSStub_ab4e {
  strings:
    $key_ab4e = { ff 26 [2] 8b 3e [2] cc 3c [2] 8b 2d [2] c5 21 [2] c9 2b [2] de 20 [2] c5 6e [2] f8 }

  condition:
    any of them
}