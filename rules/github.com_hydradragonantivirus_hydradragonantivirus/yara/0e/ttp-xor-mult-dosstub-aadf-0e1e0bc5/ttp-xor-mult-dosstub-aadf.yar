rule TTP_XOR_MULT_DOSStub_aadf {
  strings:
    $key_aadf = { fe b7 [2] 8a af [2] cd ad [2] 8a bc [2] c4 b0 [2] c8 ba [2] df b1 [2] c4 ff [2] f9 }

  condition:
    any of them
}