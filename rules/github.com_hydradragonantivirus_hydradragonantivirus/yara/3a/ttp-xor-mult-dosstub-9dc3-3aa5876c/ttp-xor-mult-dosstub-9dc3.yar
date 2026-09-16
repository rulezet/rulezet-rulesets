rule TTP_XOR_MULT_DOSStub_9dc3 {
  strings:
    $key_9dc3 = { c9 ab [2] bd b3 [2] fa b1 [2] bd a0 [2] f3 ac [2] ff a6 [2] e8 ad [2] f3 e3 [2] ce }

  condition:
    any of them
}