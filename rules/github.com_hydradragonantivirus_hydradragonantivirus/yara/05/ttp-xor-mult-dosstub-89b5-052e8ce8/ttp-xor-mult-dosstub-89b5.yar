rule TTP_XOR_MULT_DOSStub_89b5 {
  strings:
    $key_89b5 = { dd dd [2] a9 c5 [2] ee c7 [2] a9 d6 [2] e7 da [2] eb d0 [2] fc db [2] e7 95 [2] da }

  condition:
    any of them
}