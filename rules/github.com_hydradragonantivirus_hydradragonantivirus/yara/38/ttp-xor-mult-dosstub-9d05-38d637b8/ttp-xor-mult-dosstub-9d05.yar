rule TTP_XOR_MULT_DOSStub_9d05 {
  strings:
    $key_9d05 = { c9 6d [2] bd 75 [2] fa 77 [2] bd 66 [2] f3 6a [2] ff 60 [2] e8 6b [2] f3 25 [2] ce }

  condition:
    any of them
}