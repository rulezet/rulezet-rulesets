rule TTP_XOR_MULT_DOSStub_9da1 {
  strings:
    $key_9da1 = { c9 c9 [2] bd d1 [2] fa d3 [2] bd c2 [2] f3 ce [2] ff c4 [2] e8 cf [2] f3 81 [2] ce }

  condition:
    any of them
}