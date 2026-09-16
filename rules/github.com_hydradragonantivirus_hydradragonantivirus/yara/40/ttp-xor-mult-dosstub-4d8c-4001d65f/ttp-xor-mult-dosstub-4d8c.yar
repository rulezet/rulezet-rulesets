rule TTP_XOR_MULT_DOSStub_4d8c {
  strings:
    $key_4d8c = { 19 e4 [2] 6d fc [2] 2a fe [2] 6d ef [2] 23 e3 [2] 2f e9 [2] 38 e2 [2] 23 ac [2] 1e }

  condition:
    any of them
}