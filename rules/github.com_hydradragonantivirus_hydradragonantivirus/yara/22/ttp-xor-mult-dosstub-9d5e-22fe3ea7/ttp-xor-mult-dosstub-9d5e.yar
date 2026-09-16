rule TTP_XOR_MULT_DOSStub_9d5e {
  strings:
    $key_9d5e = { c9 36 [2] bd 2e [2] fa 2c [2] bd 3d [2] f3 31 [2] ff 3b [2] e8 30 [2] f3 7e [2] ce }

  condition:
    any of them
}