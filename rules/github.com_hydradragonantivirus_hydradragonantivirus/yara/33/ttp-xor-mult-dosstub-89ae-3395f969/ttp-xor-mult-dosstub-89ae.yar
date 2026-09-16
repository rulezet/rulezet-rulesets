rule TTP_XOR_MULT_DOSStub_89ae {
  strings:
    $key_89ae = { dd c6 [2] a9 de [2] ee dc [2] a9 cd [2] e7 c1 [2] eb cb [2] fc c0 [2] e7 8e [2] da }

  condition:
    any of them
}