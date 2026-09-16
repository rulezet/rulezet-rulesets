rule TTP_XOR_MULT_DOSStub_0c83 {
  strings:
    $key_0c83 = { 58 eb [2] 2c f3 [2] 6b f1 [2] 2c e0 [2] 62 ec [2] 6e e6 [2] 79 ed [2] 62 a3 [2] 5f }

  condition:
    any of them
}