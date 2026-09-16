rule TTP_XOR_MULT_DOSStub_1e8c {
  strings:
    $key_1e8c = { 4a e4 [2] 3e fc [2] 79 fe [2] 3e ef [2] 70 e3 [2] 7c e9 [2] 6b e2 [2] 70 ac [2] 4d }

  condition:
    any of them
}