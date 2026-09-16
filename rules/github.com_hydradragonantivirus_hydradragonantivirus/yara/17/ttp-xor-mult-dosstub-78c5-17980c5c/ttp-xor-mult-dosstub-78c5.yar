rule TTP_XOR_MULT_DOSStub_78c5 {
  strings:
    $key_78c5 = { 2c ad [2] 58 b5 [2] 1f b7 [2] 58 a6 [2] 16 aa [2] 1a a0 [2] 0d ab [2] 16 e5 [2] 2b }

  condition:
    any of them
}