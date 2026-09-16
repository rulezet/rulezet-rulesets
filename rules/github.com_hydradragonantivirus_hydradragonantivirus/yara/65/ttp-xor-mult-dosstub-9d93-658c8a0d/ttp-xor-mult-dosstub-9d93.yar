rule TTP_XOR_MULT_DOSStub_9d93 {
  strings:
    $key_9d93 = { c9 fb [2] bd e3 [2] fa e1 [2] bd f0 [2] f3 fc [2] ff f6 [2] e8 fd [2] f3 b3 [2] ce }

  condition:
    any of them
}