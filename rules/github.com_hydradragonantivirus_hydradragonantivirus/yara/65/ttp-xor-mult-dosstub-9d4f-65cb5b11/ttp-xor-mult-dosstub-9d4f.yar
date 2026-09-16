rule TTP_XOR_MULT_DOSStub_9d4f {
  strings:
    $key_9d4f = { c9 27 [2] bd 3f [2] fa 3d [2] bd 2c [2] f3 20 [2] ff 2a [2] e8 21 [2] f3 6f [2] ce }

  condition:
    any of them
}