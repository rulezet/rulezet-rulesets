rule TTP_XOR_MULT_DOSStub_9d19 {
  strings:
    $key_9d19 = { c9 71 [2] bd 69 [2] fa 6b [2] bd 7a [2] f3 76 [2] ff 7c [2] e8 77 [2] f3 39 [2] ce }

  condition:
    any of them
}