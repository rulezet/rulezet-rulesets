rule TTP_XOR_MULT_DOSStub_9d4c {
  strings:
    $key_9d4c = { c9 24 [2] bd 3c [2] fa 3e [2] bd 2f [2] f3 23 [2] ff 29 [2] e8 22 [2] f3 6c [2] ce }

  condition:
    any of them
}