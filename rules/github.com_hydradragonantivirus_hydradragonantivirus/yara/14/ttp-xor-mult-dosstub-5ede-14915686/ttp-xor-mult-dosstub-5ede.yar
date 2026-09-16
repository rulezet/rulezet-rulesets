rule TTP_XOR_MULT_DOSStub_5ede {
  strings:
    $key_5ede = { 0a b6 [2] 7e ae [2] 39 ac [2] 7e bd [2] 30 b1 [2] 3c bb [2] 2b b0 [2] 30 fe [2] 0d }

  condition:
    any of them
}