rule TTP_XOR_MULT_DOSStub_ab0d {
  strings:
    $key_ab0d = { ff 65 [2] 8b 7d [2] cc 7f [2] 8b 6e [2] c5 62 [2] c9 68 [2] de 63 [2] c5 2d [2] f8 }

  condition:
    any of them
}