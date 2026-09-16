rule TTP_XOR_MULT_DOSStub_9d25 {
  strings:
    $key_9d25 = { c9 4d [2] bd 55 [2] fa 57 [2] bd 46 [2] f3 4a [2] ff 40 [2] e8 4b [2] f3 05 [2] ce }

  condition:
    any of them
}