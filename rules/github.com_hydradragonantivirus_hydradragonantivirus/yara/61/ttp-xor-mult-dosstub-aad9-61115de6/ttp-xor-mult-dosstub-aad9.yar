rule TTP_XOR_MULT_DOSStub_aad9 {
  strings:
    $key_aad9 = { fe b1 [2] 8a a9 [2] cd ab [2] 8a ba [2] c4 b6 [2] c8 bc [2] df b7 [2] c4 f9 [2] f9 }

  condition:
    any of them
}