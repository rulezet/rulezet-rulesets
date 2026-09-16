rule TTP_XOR_MULT_DOSStub_2c85 {
  strings:
    $key_2c85 = { 78 ed [2] 0c f5 [2] 4b f7 [2] 0c e6 [2] 42 ea [2] 4e e0 [2] 59 eb [2] 42 a5 [2] 7f }

  condition:
    any of them
}