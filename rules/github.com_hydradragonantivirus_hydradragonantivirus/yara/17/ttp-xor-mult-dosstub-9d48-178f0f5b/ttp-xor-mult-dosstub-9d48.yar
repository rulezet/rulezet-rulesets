rule TTP_XOR_MULT_DOSStub_9d48 {
  strings:
    $key_9d48 = { c9 20 [2] bd 38 [2] fa 3a [2] bd 2b [2] f3 27 [2] ff 2d [2] e8 26 [2] f3 68 [2] ce }

  condition:
    any of them
}