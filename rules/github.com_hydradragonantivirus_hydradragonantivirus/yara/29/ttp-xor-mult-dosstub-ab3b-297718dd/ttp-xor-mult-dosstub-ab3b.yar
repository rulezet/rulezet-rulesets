rule TTP_XOR_MULT_DOSStub_ab3b {
  strings:
    $key_ab3b = { ff 53 [2] 8b 4b [2] cc 49 [2] 8b 58 [2] c5 54 [2] c9 5e [2] de 55 [2] c5 1b [2] f8 }

  condition:
    any of them
}