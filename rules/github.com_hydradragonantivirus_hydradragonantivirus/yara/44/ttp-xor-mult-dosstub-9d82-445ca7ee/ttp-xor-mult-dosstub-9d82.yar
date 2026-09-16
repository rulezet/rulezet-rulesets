rule TTP_XOR_MULT_DOSStub_9d82 {
  strings:
    $key_9d82 = { c9 ea [2] bd f2 [2] fa f0 [2] bd e1 [2] f3 ed [2] ff e7 [2] e8 ec [2] f3 a2 [2] ce }

  condition:
    any of them
}