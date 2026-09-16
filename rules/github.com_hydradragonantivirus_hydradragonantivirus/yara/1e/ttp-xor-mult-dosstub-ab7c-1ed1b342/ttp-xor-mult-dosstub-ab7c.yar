rule TTP_XOR_MULT_DOSStub_ab7c {
  strings:
    $key_ab7c = { ff 14 [2] 8b 0c [2] cc 0e [2] 8b 1f [2] c5 13 [2] c9 19 [2] de 12 [2] c5 5c [2] f8 }

  condition:
    any of them
}