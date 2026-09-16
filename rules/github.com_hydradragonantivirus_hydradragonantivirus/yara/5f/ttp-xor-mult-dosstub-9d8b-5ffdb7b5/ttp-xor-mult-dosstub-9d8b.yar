rule TTP_XOR_MULT_DOSStub_9d8b {
  strings:
    $key_9d8b = { c9 e3 [2] bd fb [2] fa f9 [2] bd e8 [2] f3 e4 [2] ff ee [2] e8 e5 [2] f3 ab [2] ce }

  condition:
    any of them
}