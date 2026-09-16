rule TTP_XOR_MULT_DOSStub_899b {
  strings:
    $key_899b = { dd f3 [2] a9 eb [2] ee e9 [2] a9 f8 [2] e7 f4 [2] eb fe [2] fc f5 [2] e7 bb [2] da }

  condition:
    any of them
}