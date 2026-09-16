rule TTP_XOR_MULT_DOSStub_6cdf {
  strings:
    $key_6cdf = { 38 b7 [2] 4c af [2] 0b ad [2] 4c bc [2] 02 b0 [2] 0e ba [2] 19 b1 [2] 02 ff [2] 3f }

  condition:
    any of them
}