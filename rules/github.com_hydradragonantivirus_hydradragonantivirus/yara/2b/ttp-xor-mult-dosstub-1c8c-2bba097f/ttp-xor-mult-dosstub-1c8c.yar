rule TTP_XOR_MULT_DOSStub_1c8c {
  strings:
    $key_1c8c = { 48 e4 [2] 3c fc [2] 7b fe [2] 3c ef [2] 72 e3 [2] 7e e9 [2] 69 e2 [2] 72 ac [2] 4f }

  condition:
    any of them
}