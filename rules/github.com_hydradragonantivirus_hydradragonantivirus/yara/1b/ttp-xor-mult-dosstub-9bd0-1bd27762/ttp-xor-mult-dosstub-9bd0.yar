rule TTP_XOR_MULT_DOSStub_9bd0 {
  strings:
    $key_9bd0 = { cf b8 [2] bb a0 [2] fc a2 [2] bb b3 [2] f5 bf [2] f9 b5 [2] ee be [2] f5 f0 [2] c8 }

  condition:
    any of them
}