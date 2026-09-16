rule TTP_XOR_MULT_DOSStub_9df7 {
  strings:
    $key_9df7 = { c9 9f [2] bd 87 [2] fa 85 [2] bd 94 [2] f3 98 [2] ff 92 [2] e8 99 [2] f3 d7 [2] ce }

  condition:
    any of them
}