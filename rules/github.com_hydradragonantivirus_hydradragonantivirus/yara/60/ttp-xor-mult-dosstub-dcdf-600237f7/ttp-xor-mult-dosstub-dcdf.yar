rule TTP_XOR_MULT_DOSStub_dcdf {
  strings:
    $key_dcdf = { 88 b7 [2] fc af [2] bb ad [2] fc bc [2] b2 b0 [2] be ba [2] a9 b1 [2] b2 ff [2] 8f }

  condition:
    any of them
}