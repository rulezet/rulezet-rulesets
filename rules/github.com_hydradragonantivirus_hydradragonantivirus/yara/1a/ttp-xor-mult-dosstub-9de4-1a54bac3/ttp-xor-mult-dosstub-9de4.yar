rule TTP_XOR_MULT_DOSStub_9de4 {
  strings:
    $key_9de4 = { c9 8c [2] bd 94 [2] fa 96 [2] bd 87 [2] f3 8b [2] ff 81 [2] e8 8a [2] f3 c4 [2] ce }

  condition:
    any of them
}