rule TTP_XOR_MULT_DOSStub_9d38 {
  strings:
    $key_9d38 = { c9 50 [2] bd 48 [2] fa 4a [2] bd 5b [2] f3 57 [2] ff 5d [2] e8 56 [2] f3 18 [2] ce }

  condition:
    any of them
}