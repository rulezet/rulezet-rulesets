rule TTP_XOR_MULT_DOSStub_58c3 {
  strings:
    $key_58c3 = { 0c ab [2] 78 b3 [2] 3f b1 [2] 78 a0 [2] 36 ac [2] 3a a6 [2] 2d ad [2] 36 e3 [2] 0b }

  condition:
    any of them
}