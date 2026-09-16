rule TTP_XOR_MULT_DOSStub_7f9a {
  strings:
    $key_7f9a = { 2b f2 [2] 5f ea [2] 18 e8 [2] 5f f9 [2] 11 f5 [2] 1d ff [2] 0a f4 [2] 11 ba [2] 2c }

  condition:
    any of them
}