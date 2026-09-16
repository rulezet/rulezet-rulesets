rule TTP_XOR_MULT_DOSStub_89b2 {
  strings:
    $key_89b2 = { dd da [2] a9 c2 [2] ee c0 [2] a9 d1 [2] e7 dd [2] eb d7 [2] fc dc [2] e7 92 [2] da }

  condition:
    any of them
}