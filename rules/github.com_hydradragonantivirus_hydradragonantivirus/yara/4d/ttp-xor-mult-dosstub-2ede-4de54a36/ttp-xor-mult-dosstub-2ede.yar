rule TTP_XOR_MULT_DOSStub_2ede {
  strings:
    $key_2ede = { 7a b6 [2] 0e ae [2] 49 ac [2] 0e bd [2] 40 b1 [2] 4c bb [2] 5b b0 [2] 40 fe [2] 7d }

  condition:
    any of them
}