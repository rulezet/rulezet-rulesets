rule TTP_XOR_MULT_DOSStub_5cdf {
  strings:
    $key_5cdf = { 08 b7 [2] 7c af [2] 3b ad [2] 7c bc [2] 32 b0 [2] 3e ba [2] 29 b1 [2] 32 ff [2] 0f }

  condition:
    any of them
}