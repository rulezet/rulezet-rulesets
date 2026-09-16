rule TTP_XOR_MULT_DOSStub_1a8c {
  strings:
    $key_1a8c = { 4e e4 [2] 3a fc [2] 7d fe [2] 3a ef [2] 74 e3 [2] 78 e9 [2] 6f e2 [2] 74 ac [2] 49 }

  condition:
    any of them
}