rule TTP_XOR_MULT_DOSStub_9d3b {
  strings:
    $key_9d3b = { c9 53 [2] bd 4b [2] fa 49 [2] bd 58 [2] f3 54 [2] ff 5e [2] e8 55 [2] f3 1b [2] ce }

  condition:
    any of them
}