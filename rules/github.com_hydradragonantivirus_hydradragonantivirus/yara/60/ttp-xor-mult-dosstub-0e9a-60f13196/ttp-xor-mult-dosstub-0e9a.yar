rule TTP_XOR_MULT_DOSStub_0e9a {
  strings:
    $key_0e9a = { 5a f2 [2] 2e ea [2] 69 e8 [2] 2e f9 [2] 60 f5 [2] 6c ff [2] 7b f4 [2] 60 ba [2] 5d }

  condition:
    any of them
}