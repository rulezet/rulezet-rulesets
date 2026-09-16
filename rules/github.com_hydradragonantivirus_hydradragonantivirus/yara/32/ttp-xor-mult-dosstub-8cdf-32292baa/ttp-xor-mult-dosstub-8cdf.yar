rule TTP_XOR_MULT_DOSStub_8cdf {
  strings:
    $key_8cdf = { d8 b7 [2] ac af [2] eb ad [2] ac bc [2] e2 b0 [2] ee ba [2] f9 b1 [2] e2 ff [2] df }

  condition:
    any of them
}