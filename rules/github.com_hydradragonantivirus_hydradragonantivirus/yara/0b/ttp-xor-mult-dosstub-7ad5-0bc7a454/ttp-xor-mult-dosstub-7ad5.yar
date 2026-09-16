rule TTP_XOR_MULT_DOSStub_7ad5 {
  strings:
    $key_7ad5 = { 2e bd [2] 5a a5 [2] 1d a7 [2] 5a b6 [2] 14 ba [2] 18 b0 [2] 0f bb [2] 14 f5 [2] 29 }

  condition:
    any of them
}