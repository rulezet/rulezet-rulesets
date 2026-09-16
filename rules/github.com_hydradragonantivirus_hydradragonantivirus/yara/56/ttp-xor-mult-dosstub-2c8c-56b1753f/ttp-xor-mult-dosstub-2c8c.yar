rule TTP_XOR_MULT_DOSStub_2c8c {
  strings:
    $key_2c8c = { 78 e4 [2] 0c fc [2] 4b fe [2] 0c ef [2] 42 e3 [2] 4e e9 [2] 59 e2 [2] 42 ac [2] 7f }

  condition:
    any of them
}