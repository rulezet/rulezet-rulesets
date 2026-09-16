rule TTP_XOR_MULT_DOSStub_9d01 {
  strings:
    $key_9d01 = { c9 69 [2] bd 71 [2] fa 73 [2] bd 62 [2] f3 6e [2] ff 64 [2] e8 6f [2] f3 21 [2] ce }

  condition:
    any of them
}