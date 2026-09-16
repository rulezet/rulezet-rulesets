rule TTP_XOR_MULT_DOSStub_9d88 {
  strings:
    $key_9d88 = { c9 e0 [2] bd f8 [2] fa fa [2] bd eb [2] f3 e7 [2] ff ed [2] e8 e6 [2] f3 a8 [2] ce }

  condition:
    any of them
}