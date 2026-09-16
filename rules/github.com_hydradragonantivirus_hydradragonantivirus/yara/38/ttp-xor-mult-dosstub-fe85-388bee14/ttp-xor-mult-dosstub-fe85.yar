rule TTP_XOR_MULT_DOSStub_fe85 {
  strings:
    $key_fe85 = { aa ed [2] de f5 [2] 99 f7 [2] de e6 [2] 90 ea [2] 9c e0 [2] 8b eb [2] 90 a5 [2] ad }

  condition:
    any of them
}