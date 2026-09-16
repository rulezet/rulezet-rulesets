rule TTP_XOR_MULT_DOSStub_9d0f {
  strings:
    $key_9d0f = { c9 67 [2] bd 7f [2] fa 7d [2] bd 6c [2] f3 60 [2] ff 6a [2] e8 61 [2] f3 2f [2] ce }

  condition:
    any of them
}