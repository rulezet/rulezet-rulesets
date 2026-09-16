rule TTP_XOR_MULT_DOSStub_9d43 {
  strings:
    $key_9d43 = { c9 2b [2] bd 33 [2] fa 31 [2] bd 20 [2] f3 2c [2] ff 26 [2] e8 2d [2] f3 63 [2] ce }

  condition:
    any of them
}