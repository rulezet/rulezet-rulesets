rule TTP_XOR_MULT_DOSStub_4bd3 {
  strings:
    $key_4bd3 = { 1f bb [2] 6b a3 [2] 2c a1 [2] 6b b0 [2] 25 bc [2] 29 b6 [2] 3e bd [2] 25 f3 [2] 18 }

  condition:
    any of them
}