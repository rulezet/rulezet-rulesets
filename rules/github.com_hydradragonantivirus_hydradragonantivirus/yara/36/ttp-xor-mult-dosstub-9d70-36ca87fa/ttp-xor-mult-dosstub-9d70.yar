rule TTP_XOR_MULT_DOSStub_9d70 {
  strings:
    $key_9d70 = { c9 18 [2] bd 00 [2] fa 02 [2] bd 13 [2] f3 1f [2] ff 15 [2] e8 1e [2] f3 50 [2] ce }

  condition:
    any of them
}