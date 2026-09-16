rule TTP_XOR_MULT_DOSStub_9d54 {
  strings:
    $key_9d54 = { c9 3c [2] bd 24 [2] fa 26 [2] bd 37 [2] f3 3b [2] ff 31 [2] e8 3a [2] f3 74 [2] ce }

  condition:
    any of them
}