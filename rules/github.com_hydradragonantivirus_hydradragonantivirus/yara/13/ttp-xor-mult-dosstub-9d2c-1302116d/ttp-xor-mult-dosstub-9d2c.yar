rule TTP_XOR_MULT_DOSStub_9d2c {
  strings:
    $key_9d2c = { c9 44 [2] bd 5c [2] fa 5e [2] bd 4f [2] f3 43 [2] ff 49 [2] e8 42 [2] f3 0c [2] ce }

  condition:
    any of them
}