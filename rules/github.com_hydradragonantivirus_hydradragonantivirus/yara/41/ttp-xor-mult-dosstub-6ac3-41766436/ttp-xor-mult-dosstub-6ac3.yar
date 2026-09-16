rule TTP_XOR_MULT_DOSStub_6ac3 {
  strings:
    $key_6ac3 = { 3e ab [2] 4a b3 [2] 0d b1 [2] 4a a0 [2] 04 ac [2] 08 a6 [2] 1f ad [2] 04 e3 [2] 39 }

  condition:
    any of them
}