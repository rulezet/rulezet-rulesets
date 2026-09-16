rule TTP_XOR_MULT_DOSStub_9da2 {
  strings:
    $key_9da2 = { c9 ca [2] bd d2 [2] fa d0 [2] bd c1 [2] f3 cd [2] ff c7 [2] e8 cc [2] f3 82 [2] ce }

  condition:
    any of them
}