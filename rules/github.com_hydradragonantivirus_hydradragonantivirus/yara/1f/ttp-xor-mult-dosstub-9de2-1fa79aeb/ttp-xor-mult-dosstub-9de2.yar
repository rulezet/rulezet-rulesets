rule TTP_XOR_MULT_DOSStub_9de2 {
  strings:
    $key_9de2 = { c9 8a [2] bd 92 [2] fa 90 [2] bd 81 [2] f3 8d [2] ff 87 [2] e8 8c [2] f3 c2 [2] ce }

  condition:
    any of them
}