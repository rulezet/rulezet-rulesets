rule TTP_XOR_MULT_DOSStub_9d6a {
  strings:
    $key_9d6a = { c9 02 [2] bd 1a [2] fa 18 [2] bd 09 [2] f3 05 [2] ff 0f [2] e8 04 [2] f3 4a [2] ce }

  condition:
    any of them
}