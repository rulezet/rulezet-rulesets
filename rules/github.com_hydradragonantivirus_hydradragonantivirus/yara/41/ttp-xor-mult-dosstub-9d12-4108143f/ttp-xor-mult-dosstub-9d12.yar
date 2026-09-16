rule TTP_XOR_MULT_DOSStub_9d12 {
  strings:
    $key_9d12 = { c9 7a [2] bd 62 [2] fa 60 [2] bd 71 [2] f3 7d [2] ff 77 [2] e8 7c [2] f3 32 [2] ce }

  condition:
    any of them
}