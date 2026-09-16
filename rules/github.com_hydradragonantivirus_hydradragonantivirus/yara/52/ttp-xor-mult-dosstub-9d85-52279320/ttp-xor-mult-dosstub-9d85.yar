rule TTP_XOR_MULT_DOSStub_9d85 {
  strings:
    $key_9d85 = { c9 ed [2] bd f5 [2] fa f7 [2] bd e6 [2] f3 ea [2] ff e0 [2] e8 eb [2] f3 a5 [2] ce }

  condition:
    any of them
}