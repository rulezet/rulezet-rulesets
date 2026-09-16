rule TTP_XOR_MULT_DOSStub_fe97 {
  strings:
    $key_fe97 = { aa ff [2] de e7 [2] 99 e5 [2] de f4 [2] 90 f8 [2] 9c f2 [2] 8b f9 [2] 90 b7 [2] ad }

  condition:
    any of them
}