rule TTP_XOR_MULT_DOSStub_2c84 {
  strings:
    $key_2c84 = { 78 ec [2] 0c f4 [2] 4b f6 [2] 0c e7 [2] 42 eb [2] 4e e1 [2] 59 ea [2] 42 a4 [2] 7f }

  condition:
    any of them
}