rule TTP_XOR_MULT_DOSStub_9d8f {
  strings:
    $key_9d8f = { c9 e7 [2] bd ff [2] fa fd [2] bd ec [2] f3 e0 [2] ff ea [2] e8 e1 [2] f3 af [2] ce }

  condition:
    any of them
}