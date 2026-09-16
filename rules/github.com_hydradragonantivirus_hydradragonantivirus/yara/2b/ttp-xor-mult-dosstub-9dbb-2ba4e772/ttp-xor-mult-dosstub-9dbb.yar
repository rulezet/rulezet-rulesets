rule TTP_XOR_MULT_DOSStub_9dbb {
  strings:
    $key_9dbb = { c9 d3 [2] bd cb [2] fa c9 [2] bd d8 [2] f3 d4 [2] ff de [2] e8 d5 [2] f3 9b [2] ce }

  condition:
    any of them
}