rule TTP_XOR_MULT_DOSStub_9d8a {
  strings:
    $key_9d8a = { c9 e2 [2] bd fa [2] fa f8 [2] bd e9 [2] f3 e5 [2] ff ef [2] e8 e4 [2] f3 aa [2] ce }

  condition:
    any of them
}