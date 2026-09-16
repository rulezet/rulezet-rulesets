rule TTP_XOR_MULT_DOSStub_9d24 {
  strings:
    $key_9d24 = { c9 4c [2] bd 54 [2] fa 56 [2] bd 47 [2] f3 4b [2] ff 41 [2] e8 4a [2] f3 04 [2] ce }

  condition:
    any of them
}