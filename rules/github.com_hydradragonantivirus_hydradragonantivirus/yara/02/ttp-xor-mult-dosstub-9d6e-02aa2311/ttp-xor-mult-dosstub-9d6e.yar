rule TTP_XOR_MULT_DOSStub_9d6e {
  strings:
    $key_9d6e = { c9 06 [2] bd 1e [2] fa 1c [2] bd 0d [2] f3 01 [2] ff 0b [2] e8 00 [2] f3 4e [2] ce }

  condition:
    any of them
}