rule TTP_XOR_MULT_DOSStub_9d17 {
  strings:
    $key_9d17 = { c9 7f [2] bd 67 [2] fa 65 [2] bd 74 [2] f3 78 [2] ff 72 [2] e8 79 [2] f3 37 [2] ce }

  condition:
    any of them
}