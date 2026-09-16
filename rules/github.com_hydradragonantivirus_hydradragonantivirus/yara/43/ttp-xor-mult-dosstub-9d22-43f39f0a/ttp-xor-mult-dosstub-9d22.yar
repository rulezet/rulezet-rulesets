rule TTP_XOR_MULT_DOSStub_9d22 {
  strings:
    $key_9d22 = { c9 4a [2] bd 52 [2] fa 50 [2] bd 41 [2] f3 4d [2] ff 47 [2] e8 4c [2] f3 02 [2] ce }

  condition:
    any of them
}