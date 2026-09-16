rule TTP_XOR_MULT_DOSStub_9d4a {
  strings:
    $key_9d4a = { c9 22 [2] bd 3a [2] fa 38 [2] bd 29 [2] f3 25 [2] ff 2f [2] e8 24 [2] f3 6a [2] ce }

  condition:
    any of them
}