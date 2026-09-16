rule TTP_XOR_MULT_DOSStub_3c8c {
  strings:
    $key_3c8c = { 68 e4 [2] 1c fc [2] 5b fe [2] 1c ef [2] 52 e3 [2] 5e e9 [2] 49 e2 [2] 52 ac [2] 6f }

  condition:
    any of them
}