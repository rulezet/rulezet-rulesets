rule TTP_XOR_MULT_DOSStub_9d44 {
  strings:
    $key_9d44 = { c9 2c [2] bd 34 [2] fa 36 [2] bd 27 [2] f3 2b [2] ff 21 [2] e8 2a [2] f3 64 [2] ce }

  condition:
    any of them
}