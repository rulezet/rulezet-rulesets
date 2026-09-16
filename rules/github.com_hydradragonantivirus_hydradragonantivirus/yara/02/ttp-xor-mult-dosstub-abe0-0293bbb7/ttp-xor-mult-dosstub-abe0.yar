rule TTP_XOR_MULT_DOSStub_abe0 {
  strings:
    $key_abe0 = { ff 88 [2] 8b 90 [2] cc 92 [2] 8b 83 [2] c5 8f [2] c9 85 [2] de 8e [2] c5 c0 [2] f8 }

  condition:
    any of them
}