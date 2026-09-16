rule TTP_XOR_MULT_DOSStub_5e8c {
  strings:
    $key_5e8c = { 0a e4 [2] 7e fc [2] 39 fe [2] 7e ef [2] 30 e3 [2] 3c e9 [2] 2b e2 [2] 30 ac [2] 0d }

  condition:
    any of them
}