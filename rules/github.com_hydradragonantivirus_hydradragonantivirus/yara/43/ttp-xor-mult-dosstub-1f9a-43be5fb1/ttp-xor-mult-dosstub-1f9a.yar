rule TTP_XOR_MULT_DOSStub_1f9a {
  strings:
    $key_1f9a = { 4b f2 [2] 3f ea [2] 78 e8 [2] 3f f9 [2] 71 f5 [2] 7d ff [2] 6a f4 [2] 71 ba [2] 4c }

  condition:
    any of them
}