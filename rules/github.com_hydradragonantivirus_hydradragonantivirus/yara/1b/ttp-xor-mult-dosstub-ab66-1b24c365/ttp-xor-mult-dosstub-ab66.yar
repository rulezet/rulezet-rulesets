rule TTP_XOR_MULT_DOSStub_ab66 {
  strings:
    $key_ab66 = { ff 0e [2] 8b 16 [2] cc 14 [2] 8b 05 [2] c5 09 [2] c9 03 [2] de 08 [2] c5 46 [2] f8 }

  condition:
    any of them
}