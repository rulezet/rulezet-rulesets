rule TTP_XOR_MULT_DOSStub_ab2c {
  strings:
    $key_ab2c = { ff 44 [2] 8b 5c [2] cc 5e [2] 8b 4f [2] c5 43 [2] c9 49 [2] de 42 [2] c5 0c [2] f8 }

  condition:
    any of them
}