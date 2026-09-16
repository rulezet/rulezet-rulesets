rule TTP_XOR_MULT_DOSStub_9dfc {
  strings:
    $key_9dfc = { c9 94 [2] bd 8c [2] fa 8e [2] bd 9f [2] f3 93 [2] ff 99 [2] e8 92 [2] f3 dc [2] ce }

  condition:
    any of them
}