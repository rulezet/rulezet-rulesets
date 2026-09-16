rule TTP_XOR_MULT_DOSStub_9df9 {
  strings:
    $key_9df9 = { c9 91 [2] bd 89 [2] fa 8b [2] bd 9a [2] f3 96 [2] ff 9c [2] e8 97 [2] f3 d9 [2] ce }

  condition:
    any of them
}