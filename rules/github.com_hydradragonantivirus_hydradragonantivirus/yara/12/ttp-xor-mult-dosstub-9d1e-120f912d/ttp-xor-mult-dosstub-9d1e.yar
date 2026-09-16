rule TTP_XOR_MULT_DOSStub_9d1e {
  strings:
    $key_9d1e = { c9 76 [2] bd 6e [2] fa 6c [2] bd 7d [2] f3 71 [2] ff 7b [2] e8 70 [2] f3 3e [2] ce }

  condition:
    any of them
}