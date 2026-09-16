rule TTP_XOR_MULT_DOSStub_9da6 {
  strings:
    $key_9da6 = { c9 ce [2] bd d6 [2] fa d4 [2] bd c5 [2] f3 c9 [2] ff c3 [2] e8 c8 [2] f3 86 [2] ce }

  condition:
    any of them
}