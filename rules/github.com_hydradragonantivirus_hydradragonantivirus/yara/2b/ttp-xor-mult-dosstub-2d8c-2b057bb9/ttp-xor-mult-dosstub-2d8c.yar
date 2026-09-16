rule TTP_XOR_MULT_DOSStub_2d8c {
  strings:
    $key_2d8c = { 79 e4 [2] 0d fc [2] 4a fe [2] 0d ef [2] 43 e3 [2] 4f e9 [2] 58 e2 [2] 43 ac [2] 7e }

  condition:
    any of them
}