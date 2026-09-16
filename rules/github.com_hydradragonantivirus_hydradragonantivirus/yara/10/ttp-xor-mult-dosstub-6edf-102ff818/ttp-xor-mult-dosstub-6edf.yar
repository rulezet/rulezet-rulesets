rule TTP_XOR_MULT_DOSStub_6edf {
  strings:
    $key_6edf = { 3a b7 [2] 4e af [2] 09 ad [2] 4e bc [2] 00 b0 [2] 0c ba [2] 1b b1 [2] 00 ff [2] 3d }

  condition:
    any of them
}