rule TTP_XOR_MULT_DOSStub_1b8c {
  strings:
    $key_1b8c = { 4f e4 [2] 3b fc [2] 7c fe [2] 3b ef [2] 75 e3 [2] 79 e9 [2] 6e e2 [2] 75 ac [2] 48 }

  condition:
    any of them
}