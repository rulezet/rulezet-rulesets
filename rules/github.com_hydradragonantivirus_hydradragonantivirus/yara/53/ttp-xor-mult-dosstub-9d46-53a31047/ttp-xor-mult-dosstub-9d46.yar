rule TTP_XOR_MULT_DOSStub_9d46 {
  strings:
    $key_9d46 = { c9 2e [2] bd 36 [2] fa 34 [2] bd 25 [2] f3 29 [2] ff 23 [2] e8 28 [2] f3 66 [2] ce }

  condition:
    any of them
}