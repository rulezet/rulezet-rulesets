rule TTP_XOR_MULT_DOSStub_fe9a {
  strings:
    $key_fe9a = { aa f2 [2] de ea [2] 99 e8 [2] de f9 [2] 90 f5 [2] 9c ff [2] 8b f4 [2] 90 ba [2] ad }

  condition:
    any of them
}