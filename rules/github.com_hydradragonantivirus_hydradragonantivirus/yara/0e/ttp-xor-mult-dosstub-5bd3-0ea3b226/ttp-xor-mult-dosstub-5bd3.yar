rule TTP_XOR_MULT_DOSStub_5bd3 {
  strings:
    $key_5bd3 = { 0f bb [2] 7b a3 [2] 3c a1 [2] 7b b0 [2] 35 bc [2] 39 b6 [2] 2e bd [2] 35 f3 [2] 08 }

  condition:
    any of them
}