rule TTP_XOR_MULT_DOSStub_9d89 {
  strings:
    $key_9d89 = { c9 e1 [2] bd f9 [2] fa fb [2] bd ea [2] f3 e6 [2] ff ec [2] e8 e7 [2] f3 a9 [2] ce }

  condition:
    any of them
}