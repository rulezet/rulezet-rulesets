rule TTP_XOR_MULT_DOSStub_9da3 {
  strings:
    $key_9da3 = { c9 cb [2] bd d3 [2] fa d1 [2] bd c0 [2] f3 cc [2] ff c6 [2] e8 cd [2] f3 83 [2] ce }

  condition:
    any of them
}