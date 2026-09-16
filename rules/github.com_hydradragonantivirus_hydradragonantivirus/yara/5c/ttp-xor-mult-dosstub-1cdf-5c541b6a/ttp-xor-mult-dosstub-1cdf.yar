rule TTP_XOR_MULT_DOSStub_1cdf {
  strings:
    $key_1cdf = { 48 b7 [2] 3c af [2] 7b ad [2] 3c bc [2] 72 b0 [2] 7e ba [2] 69 b1 [2] 72 ff [2] 4f }

  condition:
    any of them
}