rule TTP_XOR_MULT_DOSStub_4ad5 {
  strings:
    $key_4ad5 = { 1e bd [2] 6a a5 [2] 2d a7 [2] 6a b6 [2] 24 ba [2] 28 b0 [2] 3f bb [2] 24 f5 [2] 19 }

  condition:
    any of them
}