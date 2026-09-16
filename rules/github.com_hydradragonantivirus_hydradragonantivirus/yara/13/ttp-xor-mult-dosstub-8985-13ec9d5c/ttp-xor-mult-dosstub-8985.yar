rule TTP_XOR_MULT_DOSStub_8985 {
  strings:
    $key_8985 = { dd ed [2] a9 f5 [2] ee f7 [2] a9 e6 [2] e7 ea [2] eb e0 [2] fc eb [2] e7 a5 [2] da }

  condition:
    any of them
}