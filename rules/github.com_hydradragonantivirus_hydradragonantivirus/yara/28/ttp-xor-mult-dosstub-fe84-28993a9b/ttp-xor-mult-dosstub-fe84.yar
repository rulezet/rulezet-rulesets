rule TTP_XOR_MULT_DOSStub_fe84 {
  strings:
    $key_fe84 = { aa ec [2] de f4 [2] 99 f6 [2] de e7 [2] 90 eb [2] 9c e1 [2] 8b ea [2] 90 a4 [2] ad }

  condition:
    any of them
}