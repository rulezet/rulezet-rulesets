rule TTP_XOR_MULT_DOSStub_9d1d {
  strings:
    $key_9d1d = { c9 75 [2] bd 6d [2] fa 6f [2] bd 7e [2] f3 72 [2] ff 78 [2] e8 73 [2] f3 3d [2] ce }

  condition:
    any of them
}