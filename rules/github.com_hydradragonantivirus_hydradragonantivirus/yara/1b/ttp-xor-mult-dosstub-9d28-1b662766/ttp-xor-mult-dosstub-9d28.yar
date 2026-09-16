rule TTP_XOR_MULT_DOSStub_9d28 {
  strings:
    $key_9d28 = { c9 40 [2] bd 58 [2] fa 5a [2] bd 4b [2] f3 47 [2] ff 4d [2] e8 46 [2] f3 08 [2] ce }

  condition:
    any of them
}