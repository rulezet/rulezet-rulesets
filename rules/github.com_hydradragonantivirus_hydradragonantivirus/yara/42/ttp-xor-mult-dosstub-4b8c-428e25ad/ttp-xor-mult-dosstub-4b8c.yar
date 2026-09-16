rule TTP_XOR_MULT_DOSStub_4b8c {
  strings:
    $key_4b8c = { 1f e4 [2] 6b fc [2] 2c fe [2] 6b ef [2] 25 e3 [2] 29 e9 [2] 3e e2 [2] 25 ac [2] 18 }

  condition:
    any of them
}