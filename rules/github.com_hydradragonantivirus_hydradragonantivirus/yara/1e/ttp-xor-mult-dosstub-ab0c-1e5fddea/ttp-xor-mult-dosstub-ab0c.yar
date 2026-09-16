rule TTP_XOR_MULT_DOSStub_ab0c {
  strings:
    $key_ab0c = { ff 64 [2] 8b 7c [2] cc 7e [2] 8b 6f [2] c5 63 [2] c9 69 [2] de 62 [2] c5 2c [2] f8 }

  condition:
    any of them
}