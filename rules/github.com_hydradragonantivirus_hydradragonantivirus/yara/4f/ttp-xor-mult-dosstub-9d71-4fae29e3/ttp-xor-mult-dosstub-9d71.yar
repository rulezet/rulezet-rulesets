rule TTP_XOR_MULT_DOSStub_9d71 {
  strings:
    $key_9d71 = { c9 19 [2] bd 01 [2] fa 03 [2] bd 12 [2] f3 1e [2] ff 14 [2] e8 1f [2] f3 51 [2] ce }

  condition:
    any of them
}