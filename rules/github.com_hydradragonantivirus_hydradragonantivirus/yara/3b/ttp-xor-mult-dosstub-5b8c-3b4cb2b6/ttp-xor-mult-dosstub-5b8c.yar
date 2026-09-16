rule TTP_XOR_MULT_DOSStub_5b8c {
  strings:
    $key_5b8c = { 0f e4 [2] 7b fc [2] 3c fe [2] 7b ef [2] 35 e3 [2] 39 e9 [2] 2e e2 [2] 35 ac [2] 08 }

  condition:
    any of them
}