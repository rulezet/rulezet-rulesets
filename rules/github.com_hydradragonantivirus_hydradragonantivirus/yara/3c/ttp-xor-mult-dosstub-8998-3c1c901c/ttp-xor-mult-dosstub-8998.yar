rule TTP_XOR_MULT_DOSStub_8998 {
  strings:
    $key_8998 = { dd f0 [2] a9 e8 [2] ee ea [2] a9 fb [2] e7 f7 [2] eb fd [2] fc f6 [2] e7 b8 [2] da }

  condition:
    any of them
}