rule TTP_XOR_MULT_DOSStub_9d0a {
  strings:
    $key_9d0a = { c9 62 [2] bd 7a [2] fa 78 [2] bd 69 [2] f3 65 [2] ff 6f [2] e8 64 [2] f3 2a [2] ce }

  condition:
    any of them
}