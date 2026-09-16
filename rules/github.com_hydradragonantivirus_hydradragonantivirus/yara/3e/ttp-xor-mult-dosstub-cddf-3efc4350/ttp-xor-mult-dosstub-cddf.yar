rule TTP_XOR_MULT_DOSStub_cddf {
  strings:
    $key_cddf = { 99 b7 [2] ed af [2] aa ad [2] ed bc [2] a3 b0 [2] af ba [2] b8 b1 [2] a3 ff [2] 9e }

  condition:
    any of them
}