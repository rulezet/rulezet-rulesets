rule TTP_XOR_MULT_DOSStub_6d8c {
  strings:
    $key_6d8c = { 39 e4 [2] 4d fc [2] 0a fe [2] 4d ef [2] 03 e3 [2] 0f e9 [2] 18 e2 [2] 03 ac [2] 3e }

  condition:
    any of them
}