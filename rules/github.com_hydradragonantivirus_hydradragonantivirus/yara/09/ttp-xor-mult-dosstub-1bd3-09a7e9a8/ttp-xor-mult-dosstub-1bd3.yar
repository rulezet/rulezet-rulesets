rule TTP_XOR_MULT_DOSStub_1bd3 {
  strings:
    $key_1bd3 = { 4f bb [2] 3b a3 [2] 7c a1 [2] 3b b0 [2] 75 bc [2] 79 b6 [2] 6e bd [2] 75 f3 [2] 48 }

  condition:
    any of them
}