rule TTP_XOR_MULT_DOSStub_ab40 {
  strings:
    $key_ab40 = { ff 28 [2] 8b 30 [2] cc 32 [2] 8b 23 [2] c5 2f [2] c9 25 [2] de 2e [2] c5 60 [2] f8 }

  condition:
    any of them
}