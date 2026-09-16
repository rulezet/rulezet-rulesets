rule TTP_XOR_MULT_DOSStub_9d45 {
  strings:
    $key_9d45 = { c9 2d [2] bd 35 [2] fa 37 [2] bd 26 [2] f3 2a [2] ff 20 [2] e8 2b [2] f3 65 [2] ce }

  condition:
    any of them
}