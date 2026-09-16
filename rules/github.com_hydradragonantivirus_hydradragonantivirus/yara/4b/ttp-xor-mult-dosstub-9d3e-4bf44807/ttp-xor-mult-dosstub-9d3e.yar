rule TTP_XOR_MULT_DOSStub_9d3e {
  strings:
    $key_9d3e = { c9 56 [2] bd 4e [2] fa 4c [2] bd 5d [2] f3 51 [2] ff 5b [2] e8 50 [2] f3 1e [2] ce }

  condition:
    any of them
}