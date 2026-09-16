rule TTP_XOR_MULT_DOSStub_3ede {
  strings:
    $key_3ede = { 6a b6 [2] 1e ae [2] 59 ac [2] 1e bd [2] 50 b1 [2] 5c bb [2] 4b b0 [2] 50 fe [2] 6d }

  condition:
    any of them
}