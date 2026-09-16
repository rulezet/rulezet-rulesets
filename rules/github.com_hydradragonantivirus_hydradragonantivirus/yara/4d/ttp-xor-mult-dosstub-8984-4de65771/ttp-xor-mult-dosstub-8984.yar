rule TTP_XOR_MULT_DOSStub_8984 {
  strings:
    $key_8984 = { dd ec [2] a9 f4 [2] ee f6 [2] a9 e7 [2] e7 eb [2] eb e1 [2] fc ea [2] e7 a4 [2] da }

  condition:
    any of them
}