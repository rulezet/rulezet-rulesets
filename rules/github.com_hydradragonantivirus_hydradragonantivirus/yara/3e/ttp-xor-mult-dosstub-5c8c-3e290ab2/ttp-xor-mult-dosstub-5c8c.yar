rule TTP_XOR_MULT_DOSStub_5c8c {
  strings:
    $key_5c8c = { 08 e4 [2] 7c fc [2] 3b fe [2] 7c ef [2] 32 e3 [2] 3e e9 [2] 29 e2 [2] 32 ac [2] 0f }

  condition:
    any of them
}