rule TTP_XOR_MULT_DOSStub_9d23 {
  strings:
    $key_9d23 = { c9 4b [2] bd 53 [2] fa 51 [2] bd 40 [2] f3 4c [2] ff 46 [2] e8 4d [2] f3 03 [2] ce }

  condition:
    any of them
}