rule TTP_XOR_MULT_DOSStub_9d62 {
  strings:
    $key_9d62 = { c9 0a [2] bd 12 [2] fa 10 [2] bd 01 [2] f3 0d [2] ff 07 [2] e8 0c [2] f3 42 [2] ce }

  condition:
    any of them
}