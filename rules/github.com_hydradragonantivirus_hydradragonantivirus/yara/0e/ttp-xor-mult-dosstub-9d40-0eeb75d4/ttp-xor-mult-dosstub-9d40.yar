rule TTP_XOR_MULT_DOSStub_9d40 {
  strings:
    $key_9d40 = { c9 28 [2] bd 30 [2] fa 32 [2] bd 23 [2] f3 2f [2] ff 25 [2] e8 2e [2] f3 60 [2] ce }

  condition:
    any of them
}