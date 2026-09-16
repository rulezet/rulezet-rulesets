rule TTP_XOR_MULT_DOSStub_9dea {
  strings:
    $key_9dea = { c9 82 [2] bd 9a [2] fa 98 [2] bd 89 [2] f3 85 [2] ff 8f [2] e8 84 [2] f3 ca [2] ce }

  condition:
    any of them
}