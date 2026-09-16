rule TTP_XOR_MULT_DOSStub_3f9a {
  strings:
    $key_3f9a = { 6b f2 [2] 1f ea [2] 58 e8 [2] 1f f9 [2] 51 f5 [2] 5d ff [2] 4a f4 [2] 51 ba [2] 6c }

  condition:
    any of them
}