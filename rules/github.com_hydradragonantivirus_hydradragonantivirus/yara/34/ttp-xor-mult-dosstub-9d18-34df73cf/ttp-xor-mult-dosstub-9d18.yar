rule TTP_XOR_MULT_DOSStub_9d18 {
  strings:
    $key_9d18 = { c9 70 [2] bd 68 [2] fa 6a [2] bd 7b [2] f3 77 [2] ff 7d [2] e8 76 [2] f3 38 [2] ce }

  condition:
    any of them
}