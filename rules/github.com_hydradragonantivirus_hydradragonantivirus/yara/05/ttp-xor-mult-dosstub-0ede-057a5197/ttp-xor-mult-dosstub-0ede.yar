rule TTP_XOR_MULT_DOSStub_0ede {
  strings:
    $key_0ede = { 5a b6 [2] 2e ae [2] 69 ac [2] 2e bd [2] 60 b1 [2] 6c bb [2] 7b b0 [2] 60 fe [2] 5d }

  condition:
    any of them
}