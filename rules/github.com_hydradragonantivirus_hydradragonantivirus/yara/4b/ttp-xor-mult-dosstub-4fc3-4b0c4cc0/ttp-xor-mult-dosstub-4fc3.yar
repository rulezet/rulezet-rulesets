rule TTP_XOR_MULT_DOSStub_4fc3 {
  strings:
    $key_4fc3 = { 1b ab [2] 6f b3 [2] 28 b1 [2] 6f a0 [2] 21 ac [2] 2d a6 [2] 3a ad [2] 21 e3 [2] 1c }

  condition:
    any of them
}