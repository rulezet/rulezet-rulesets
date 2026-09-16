rule TTP_XOR_MULT_DOSStub_89b3 {
  strings:
    $key_89b3 = { dd db [2] a9 c3 [2] ee c1 [2] a9 d0 [2] e7 dc [2] eb d6 [2] fc dd [2] e7 93 [2] da }

  condition:
    any of them
}