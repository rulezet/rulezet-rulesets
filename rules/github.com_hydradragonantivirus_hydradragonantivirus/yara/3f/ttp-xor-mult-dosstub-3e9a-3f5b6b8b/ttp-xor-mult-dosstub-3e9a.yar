rule TTP_XOR_MULT_DOSStub_3e9a {
  strings:
    $key_3e9a = { 6a f2 [2] 1e ea [2] 59 e8 [2] 1e f9 [2] 50 f5 [2] 5c ff [2] 4b f4 [2] 50 ba [2] 6d }

  condition:
    any of them
}