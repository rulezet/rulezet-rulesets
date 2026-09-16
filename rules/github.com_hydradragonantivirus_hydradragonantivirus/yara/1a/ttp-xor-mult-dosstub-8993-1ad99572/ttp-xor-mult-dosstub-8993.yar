rule TTP_XOR_MULT_DOSStub_8993 {
  strings:
    $key_8993 = { dd fb [2] a9 e3 [2] ee e1 [2] a9 f0 [2] e7 fc [2] eb f6 [2] fc fd [2] e7 b3 [2] da }

  condition:
    any of them
}