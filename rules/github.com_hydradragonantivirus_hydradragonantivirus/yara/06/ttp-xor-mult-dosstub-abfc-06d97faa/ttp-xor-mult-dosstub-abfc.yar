rule TTP_XOR_MULT_DOSStub_abfc {
  strings:
    $key_abfc = { ff 94 [2] 8b 8c [2] cc 8e [2] 8b 9f [2] c5 93 [2] c9 99 [2] de 92 [2] c5 dc [2] f8 }

  condition:
    any of them
}