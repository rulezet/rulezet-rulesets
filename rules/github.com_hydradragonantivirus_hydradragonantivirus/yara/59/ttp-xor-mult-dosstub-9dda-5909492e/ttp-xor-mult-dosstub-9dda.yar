rule TTP_XOR_MULT_DOSStub_9dda {
  strings:
    $key_9dda = { c9 b2 [2] bd aa [2] fa a8 [2] bd b9 [2] f3 b5 [2] ff bf [2] e8 b4 [2] f3 fa [2] ce }

  condition:
    any of them
}