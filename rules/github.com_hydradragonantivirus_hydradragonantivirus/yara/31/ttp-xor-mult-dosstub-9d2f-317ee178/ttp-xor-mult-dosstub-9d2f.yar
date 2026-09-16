rule TTP_XOR_MULT_DOSStub_9d2f {
  strings:
    $key_9d2f = { c9 47 [2] bd 5f [2] fa 5d [2] bd 4c [2] f3 40 [2] ff 4a [2] e8 41 [2] f3 0f [2] ce }

  condition:
    any of them
}