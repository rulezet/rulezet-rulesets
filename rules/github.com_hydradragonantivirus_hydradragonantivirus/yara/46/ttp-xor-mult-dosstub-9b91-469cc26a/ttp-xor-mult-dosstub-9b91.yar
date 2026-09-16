rule TTP_XOR_MULT_DOSStub_9b91 {
  strings:
    $key_9b91 = { cf f9 [2] bb e1 [2] fc e3 [2] bb f2 [2] f5 fe [2] f9 f4 [2] ee ff [2] f5 b1 [2] c8 }

  condition:
    any of them
}