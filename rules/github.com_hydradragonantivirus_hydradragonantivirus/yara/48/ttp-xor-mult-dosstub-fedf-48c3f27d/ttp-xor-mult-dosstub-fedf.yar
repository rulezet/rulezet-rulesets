rule TTP_XOR_MULT_DOSStub_fedf {
  strings:
    $key_fedf = { aa b7 [2] de af [2] 99 ad [2] de bc [2] 90 b0 [2] 9c ba [2] 8b b1 [2] 90 ff [2] ad }

  condition:
    any of them
}