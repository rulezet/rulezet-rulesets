rule TTP_XOR_MULT_DOSStub_9d11 {
  strings:
    $key_9d11 = { c9 79 [2] bd 61 [2] fa 63 [2] bd 72 [2] f3 7e [2] ff 74 [2] e8 7f [2] f3 31 [2] ce }

  condition:
    any of them
}