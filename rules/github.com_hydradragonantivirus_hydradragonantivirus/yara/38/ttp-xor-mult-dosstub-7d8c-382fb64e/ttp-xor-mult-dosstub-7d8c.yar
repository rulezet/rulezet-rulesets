rule TTP_XOR_MULT_DOSStub_7d8c {
  strings:
    $key_7d8c = { 29 e4 [2] 5d fc [2] 1a fe [2] 5d ef [2] 13 e3 [2] 1f e9 [2] 08 e2 [2] 13 ac [2] 2e }

  condition:
    any of them
}