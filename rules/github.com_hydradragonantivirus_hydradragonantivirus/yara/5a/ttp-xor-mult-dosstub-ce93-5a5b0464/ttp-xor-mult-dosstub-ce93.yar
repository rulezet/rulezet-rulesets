rule TTP_XOR_MULT_DOSStub_ce93 {
  strings:
    $key_ce93 = { 9a fb [2] ee e3 [2] a9 e1 [2] ee f0 [2] a0 fc [2] ac f6 [2] bb fd [2] a0 b3 [2] 9d }

  condition:
    any of them
}