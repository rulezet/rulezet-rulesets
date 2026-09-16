rule TTP_XOR_MULT_DOSStub_7b8c {
  strings:
    $key_7b8c = { 2f e4 [2] 5b fc [2] 1c fe [2] 5b ef [2] 15 e3 [2] 19 e9 [2] 0e e2 [2] 15 ac [2] 28 }

  condition:
    any of them
}