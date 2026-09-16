rule TTP_XOR_MULT_DOSStub_7ad9 {
  strings:
    $key_7ad9 = { 2e b1 [2] 5a a9 [2] 1d ab [2] 5a ba [2] 14 b6 [2] 18 bc [2] 0f b7 [2] 14 f9 [2] 29 }

  condition:
    any of them
}