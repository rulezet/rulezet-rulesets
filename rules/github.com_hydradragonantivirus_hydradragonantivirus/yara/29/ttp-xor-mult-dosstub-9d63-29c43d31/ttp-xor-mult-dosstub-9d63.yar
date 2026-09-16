rule TTP_XOR_MULT_DOSStub_9d63 {
  strings:
    $key_9d63 = { c9 0b [2] bd 13 [2] fa 11 [2] bd 00 [2] f3 0c [2] ff 06 [2] e8 0d [2] f3 43 [2] ce }

  condition:
    any of them
}