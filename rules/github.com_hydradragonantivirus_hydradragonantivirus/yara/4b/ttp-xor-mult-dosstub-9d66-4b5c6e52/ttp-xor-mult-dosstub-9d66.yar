rule TTP_XOR_MULT_DOSStub_9d66 {
  strings:
    $key_9d66 = { c9 0e [2] bd 16 [2] fa 14 [2] bd 05 [2] f3 09 [2] ff 03 [2] e8 08 [2] f3 46 [2] ce }

  condition:
    any of them
}