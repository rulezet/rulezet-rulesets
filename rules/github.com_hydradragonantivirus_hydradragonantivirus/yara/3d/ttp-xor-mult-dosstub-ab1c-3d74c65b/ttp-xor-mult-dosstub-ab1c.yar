rule TTP_XOR_MULT_DOSStub_ab1c {
  strings:
    $key_ab1c = { ff 74 [2] 8b 6c [2] cc 6e [2] 8b 7f [2] c5 73 [2] c9 79 [2] de 72 [2] c5 3c [2] f8 }

  condition:
    any of them
}