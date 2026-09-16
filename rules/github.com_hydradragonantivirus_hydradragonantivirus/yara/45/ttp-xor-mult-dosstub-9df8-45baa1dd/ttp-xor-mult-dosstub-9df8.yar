rule TTP_XOR_MULT_DOSStub_9df8 {
  strings:
    $key_9df8 = { c9 90 [2] bd 88 [2] fa 8a [2] bd 9b [2] f3 97 [2] ff 9d [2] e8 96 [2] f3 d8 [2] ce }

  condition:
    any of them
}