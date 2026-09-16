rule TTP_XOR_MULT_DOSStub_9d34 {
  strings:
    $key_9d34 = { c9 5c [2] bd 44 [2] fa 46 [2] bd 57 [2] f3 5b [2] ff 51 [2] e8 5a [2] f3 14 [2] ce }

  condition:
    any of them
}