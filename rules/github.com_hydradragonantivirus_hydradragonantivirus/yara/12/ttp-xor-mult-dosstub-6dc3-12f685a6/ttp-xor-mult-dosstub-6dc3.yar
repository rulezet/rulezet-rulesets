rule TTP_XOR_MULT_DOSStub_6dc3 {
  strings:
    $key_6dc3 = { 39 ab [2] 4d b3 [2] 0a b1 [2] 4d a0 [2] 03 ac [2] 0f a6 [2] 18 ad [2] 03 e3 [2] 3e }

  condition:
    any of them
}