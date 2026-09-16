rule TTP_XOR_MULT_DOSStub_1dc3 {
  strings:
    $key_1dc3 = { 49 ab [2] 3d b3 [2] 7a b1 [2] 3d a0 [2] 73 ac [2] 7f a6 [2] 68 ad [2] 73 e3 [2] 4e }

  condition:
    any of them
}