rule TTP_XOR_MULT_DOSStub_9d68 {
  strings:
    $key_9d68 = { c9 00 [2] bd 18 [2] fa 1a [2] bd 0b [2] f3 07 [2] ff 0d [2] e8 06 [2] f3 48 [2] ce }

  condition:
    any of them
}