rule TTP_XOR_MULT_DOSStub_ab26 {
  strings:
    $key_ab26 = { ff 4e [2] 8b 56 [2] cc 54 [2] 8b 45 [2] c5 49 [2] c9 43 [2] de 48 [2] c5 06 [2] f8 }

  condition:
    any of them
}