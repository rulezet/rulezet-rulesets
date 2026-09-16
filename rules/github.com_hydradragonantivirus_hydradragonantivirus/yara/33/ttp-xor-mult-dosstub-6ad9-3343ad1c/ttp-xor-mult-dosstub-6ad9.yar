rule TTP_XOR_MULT_DOSStub_6ad9 {
  strings:
    $key_6ad9 = { 3e b1 [2] 4a a9 [2] 0d ab [2] 4a ba [2] 04 b6 [2] 08 bc [2] 1f b7 [2] 04 f9 [2] 39 }

  condition:
    any of them
}