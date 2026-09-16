rule TTP_XOR_MULT_DOSStub_9d5b {
  strings:
    $key_9d5b = { c9 33 [2] bd 2b [2] fa 29 [2] bd 38 [2] f3 34 [2] ff 3e [2] e8 35 [2] f3 7b [2] ce }

  condition:
    any of them
}