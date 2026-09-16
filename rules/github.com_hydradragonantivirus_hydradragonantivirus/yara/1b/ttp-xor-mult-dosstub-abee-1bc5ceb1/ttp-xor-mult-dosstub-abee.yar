rule TTP_XOR_MULT_DOSStub_abee {
  strings:
    $key_abee = { ff 86 [2] 8b 9e [2] cc 9c [2] 8b 8d [2] c5 81 [2] c9 8b [2] de 80 [2] c5 ce [2] f8 }

  condition:
    any of them
}