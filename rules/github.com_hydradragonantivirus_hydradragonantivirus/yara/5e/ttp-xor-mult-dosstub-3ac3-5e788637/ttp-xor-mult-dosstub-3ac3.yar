rule TTP_XOR_MULT_DOSStub_3ac3 {
  strings:
    $key_3ac3 = { 6e ab [2] 1a b3 [2] 5d b1 [2] 1a a0 [2] 54 ac [2] 58 a6 [2] 4f ad [2] 54 e3 [2] 69 }

  condition:
    any of them
}