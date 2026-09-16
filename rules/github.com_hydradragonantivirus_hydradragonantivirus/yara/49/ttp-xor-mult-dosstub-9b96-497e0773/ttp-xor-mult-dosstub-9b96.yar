rule TTP_XOR_MULT_DOSStub_9b96 {
  strings:
    $key_9b96 = { cf fe [2] bb e6 [2] fc e4 [2] bb f5 [2] f5 f9 [2] f9 f3 [2] ee f8 [2] f5 b6 [2] c8 }

  condition:
    any of them
}