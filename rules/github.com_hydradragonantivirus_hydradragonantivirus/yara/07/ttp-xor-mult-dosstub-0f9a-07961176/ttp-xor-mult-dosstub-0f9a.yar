rule TTP_XOR_MULT_DOSStub_0f9a {
  strings:
    $key_0f9a = { 5b f2 [2] 2f ea [2] 68 e8 [2] 2f f9 [2] 61 f5 [2] 6d ff [2] 7a f4 [2] 61 ba [2] 5c }

  condition:
    any of them
}