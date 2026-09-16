rule TTP_XOR_MULT_DOSStub_7ede {
  strings:
    $key_7ede = { 2a b6 [2] 5e ae [2] 19 ac [2] 5e bd [2] 10 b1 [2] 1c bb [2] 0b b0 [2] 10 fe [2] 2d }

  condition:
    any of them
}