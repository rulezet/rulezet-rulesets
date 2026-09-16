rule TTP_XOR_MULT_DOSStub_0a8c {
  strings:
    $key_0a8c = { 5e e4 [2] 2a fc [2] 6d fe [2] 2a ef [2] 64 e3 [2] 68 e9 [2] 7f e2 [2] 64 ac [2] 59 }

  condition:
    any of them
}