rule TTP_XOR_MULT_DOSStub_ce98 {
  strings:
    $key_ce98 = { 9a f0 [2] ee e8 [2] a9 ea [2] ee fb [2] a0 f7 [2] ac fd [2] bb f6 [2] a0 b8 [2] 9d }

  condition:
    any of them
}