rule TTP_XOR_MULT_DOSStub_d038 {
  strings:
    $key_d038 = { 84 50 [2] f0 48 [2] b7 4a [2] f0 5b [2] be 57 [2] b2 5d [2] a5 56 [2] be 18 [2] 83 }

  condition:
    any of them
}