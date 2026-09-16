rule TTP_XOR_MULT_DOSStub_3a8c {
  strings:
    $key_3a8c = { 6e e4 [2] 1a fc [2] 5d fe [2] 1a ef [2] 54 e3 [2] 58 e9 [2] 4f e2 [2] 54 ac [2] 69 }

  condition:
    any of them
}