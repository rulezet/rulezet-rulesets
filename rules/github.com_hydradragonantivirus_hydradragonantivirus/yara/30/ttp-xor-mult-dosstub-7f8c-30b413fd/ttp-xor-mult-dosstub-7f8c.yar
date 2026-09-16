rule TTP_XOR_MULT_DOSStub_7f8c {
  strings:
    $key_7f8c = { 2b e4 [2] 5f fc [2] 18 fe [2] 5f ef [2] 11 e3 [2] 1d e9 [2] 0a e2 [2] 11 ac [2] 2c }

  condition:
    any of them
}