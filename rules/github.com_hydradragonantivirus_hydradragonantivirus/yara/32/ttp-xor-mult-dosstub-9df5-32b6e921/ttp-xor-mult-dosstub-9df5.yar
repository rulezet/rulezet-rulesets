rule TTP_XOR_MULT_DOSStub_9df5 {
  strings:
    $key_9df5 = { c9 9d [2] bd 85 [2] fa 87 [2] bd 96 [2] f3 9a [2] ff 90 [2] e8 9b [2] f3 d5 [2] ce }

  condition:
    any of them
}