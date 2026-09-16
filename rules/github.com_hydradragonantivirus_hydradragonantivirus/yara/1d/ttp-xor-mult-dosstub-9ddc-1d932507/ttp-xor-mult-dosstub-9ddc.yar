rule TTP_XOR_MULT_DOSStub_9ddc {
  strings:
    $key_9ddc = { c9 b4 [2] bd ac [2] fa ae [2] bd bf [2] f3 b3 [2] ff b9 [2] e8 b2 [2] f3 fc [2] ce }

  condition:
    any of them
}