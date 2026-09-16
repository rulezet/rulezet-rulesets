rule TTP_XOR_MULT_DOSStub_9d79 {
  strings:
    $key_9d79 = { c9 11 [2] bd 09 [2] fa 0b [2] bd 1a [2] f3 16 [2] ff 1c [2] e8 17 [2] f3 59 [2] ce }

  condition:
    any of them
}