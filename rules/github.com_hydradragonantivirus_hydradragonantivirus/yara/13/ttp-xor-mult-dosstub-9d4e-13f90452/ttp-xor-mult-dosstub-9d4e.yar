rule TTP_XOR_MULT_DOSStub_9d4e {
  strings:
    $key_9d4e = { c9 26 [2] bd 3e [2] fa 3c [2] bd 2d [2] f3 21 [2] ff 2b [2] e8 20 [2] f3 6e [2] ce }

  condition:
    any of them
}