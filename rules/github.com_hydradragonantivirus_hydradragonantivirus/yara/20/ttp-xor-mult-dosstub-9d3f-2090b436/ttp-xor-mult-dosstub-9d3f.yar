rule TTP_XOR_MULT_DOSStub_9d3f {
  strings:
    $key_9d3f = { c9 57 [2] bd 4f [2] fa 4d [2] bd 5c [2] f3 50 [2] ff 5a [2] e8 51 [2] f3 1f [2] ce }

  condition:
    any of them
}