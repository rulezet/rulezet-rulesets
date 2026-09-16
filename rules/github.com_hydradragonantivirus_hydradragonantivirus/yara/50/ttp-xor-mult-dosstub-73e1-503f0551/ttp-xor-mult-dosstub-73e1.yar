rule TTP_XOR_MULT_DOSStub_73e1 {
  strings:
    $key_73e1 = { 27 89 [2] 53 91 [2] 14 93 [2] 53 82 [2] 1d 8e [2] 11 84 [2] 06 8f [2] 1d c1 [2] 20 }

  condition:
    any of them
}