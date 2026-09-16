rule TTP_XOR_MULT_DOSStub_9de3 {
  strings:
    $key_9de3 = { c9 8b [2] bd 93 [2] fa 91 [2] bd 80 [2] f3 8c [2] ff 86 [2] e8 8d [2] f3 c3 [2] ce }

  condition:
    any of them
}