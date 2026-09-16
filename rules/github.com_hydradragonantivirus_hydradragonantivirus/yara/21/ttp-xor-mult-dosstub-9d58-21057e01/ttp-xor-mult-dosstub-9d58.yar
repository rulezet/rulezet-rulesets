rule TTP_XOR_MULT_DOSStub_9d58 {
  strings:
    $key_9d58 = { c9 30 [2] bd 28 [2] fa 2a [2] bd 3b [2] f3 37 [2] ff 3d [2] e8 36 [2] f3 78 [2] ce }

  condition:
    any of them
}