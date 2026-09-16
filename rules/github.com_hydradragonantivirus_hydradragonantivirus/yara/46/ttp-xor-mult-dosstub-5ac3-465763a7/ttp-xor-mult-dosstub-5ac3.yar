rule TTP_XOR_MULT_DOSStub_5ac3 {
  strings:
    $key_5ac3 = { 0e ab [2] 7a b3 [2] 3d b1 [2] 7a a0 [2] 34 ac [2] 38 a6 [2] 2f ad [2] 34 e3 [2] 09 }

  condition:
    any of them
}