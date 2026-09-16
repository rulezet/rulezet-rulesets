rule TTP_XOR_MULT_DOSStub_9d31 {
  strings:
    $key_9d31 = { c9 59 [2] bd 41 [2] fa 43 [2] bd 52 [2] f3 5e [2] ff 54 [2] e8 5f [2] f3 11 [2] ce }

  condition:
    any of them
}