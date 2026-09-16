rule TTP_XOR_MULT_DOSStub_9d60 {
  strings:
    $key_9d60 = { c9 08 [2] bd 10 [2] fa 12 [2] bd 03 [2] f3 0f [2] ff 05 [2] e8 0e [2] f3 40 [2] ce }

  condition:
    any of them
}