rule TTP_XOR_MULT_DOSStub_9d1c {
  strings:
    $key_9d1c = { c9 74 [2] bd 6c [2] fa 6e [2] bd 7f [2] f3 73 [2] ff 79 [2] e8 72 [2] f3 3c [2] ce }

  condition:
    any of them
}