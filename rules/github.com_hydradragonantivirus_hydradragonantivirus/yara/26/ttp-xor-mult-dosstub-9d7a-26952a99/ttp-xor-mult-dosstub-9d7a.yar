rule TTP_XOR_MULT_DOSStub_9d7a {
  strings:
    $key_9d7a = { c9 12 [2] bd 0a [2] fa 08 [2] bd 19 [2] f3 15 [2] ff 1f [2] e8 14 [2] f3 5a [2] ce }

  condition:
    any of them
}