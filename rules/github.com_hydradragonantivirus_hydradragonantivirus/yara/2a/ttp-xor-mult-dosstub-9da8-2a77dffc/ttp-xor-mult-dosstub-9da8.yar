rule TTP_XOR_MULT_DOSStub_9da8 {
  strings:
    $key_9da8 = { c9 c0 [2] bd d8 [2] fa da [2] bd cb [2] f3 c7 [2] ff cd [2] e8 c6 [2] f3 88 [2] ce }

  condition:
    any of them
}