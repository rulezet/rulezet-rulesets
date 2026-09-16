rule TTP_XOR_MULT_DOSStub_9b97 {
  strings:
    $key_9b97 = { cf ff [2] bb e7 [2] fc e5 [2] bb f4 [2] f5 f8 [2] f9 f2 [2] ee f9 [2] f5 b7 [2] c8 }

  condition:
    any of them
}