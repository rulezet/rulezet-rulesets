rule TTP_XOR_MULT_DOSStub_9da0 {
  strings:
    $key_9da0 = { c9 c8 [2] bd d0 [2] fa d2 [2] bd c3 [2] f3 cf [2] ff c5 [2] e8 ce [2] f3 80 [2] ce }

  condition:
    any of them
}