rule TTP_XOR_MULT_DOSStub_48c3 {
  strings:
    $key_48c3 = { 1c ab [2] 68 b3 [2] 2f b1 [2] 68 a0 [2] 26 ac [2] 2a a6 [2] 3d ad [2] 26 e3 [2] 1b }

  condition:
    any of them
}