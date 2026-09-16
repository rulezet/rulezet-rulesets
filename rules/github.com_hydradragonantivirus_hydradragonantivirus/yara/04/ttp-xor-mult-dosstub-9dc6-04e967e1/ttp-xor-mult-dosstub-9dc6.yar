rule TTP_XOR_MULT_DOSStub_9dc6 {
  strings:
    $key_9dc6 = { c9 ae [2] bd b6 [2] fa b4 [2] bd a5 [2] f3 a9 [2] ff a3 [2] e8 a8 [2] f3 e6 [2] ce }

  condition:
    any of them
}