rule TTP_XOR_MULT_DOSStub_9bd9 {
  strings:
    $key_9bd9 = { cf b1 [2] bb a9 [2] fc ab [2] bb ba [2] f5 b6 [2] f9 bc [2] ee b7 [2] f5 f9 [2] c8 }

  condition:
    any of them
}