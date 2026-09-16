rule TTP_XOR_MULT_DOSStub_3d8c {
  strings:
    $key_3d8c = { 69 e4 [2] 1d fc [2] 5a fe [2] 1d ef [2] 53 e3 [2] 5f e9 [2] 48 e2 [2] 53 ac [2] 6e }

  condition:
    any of them
}