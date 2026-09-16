rule TTP_XOR_MULT_DOSStub_9da5 {
  strings:
    $key_9da5 = { c9 cd [2] bd d5 [2] fa d7 [2] bd c6 [2] f3 ca [2] ff c0 [2] e8 cb [2] f3 85 [2] ce }

  condition:
    any of them
}