rule TTP_XOR_MULT_DOSStub_78a2 {
  strings:
    $key_78a2 = { 2c ca [2] 58 d2 [2] 1f d0 [2] 58 c1 [2] 16 cd [2] 1a c7 [2] 0d cc [2] 16 82 [2] 2b }

  condition:
    any of them
}