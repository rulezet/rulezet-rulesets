rule TTP_XOR_MULT_DOSStub_9bdd {
  strings:
    $key_9bdd = { cf b5 [2] bb ad [2] fc af [2] bb be [2] f5 b2 [2] f9 b8 [2] ee b3 [2] f5 fd [2] c8 }

  condition:
    any of them
}