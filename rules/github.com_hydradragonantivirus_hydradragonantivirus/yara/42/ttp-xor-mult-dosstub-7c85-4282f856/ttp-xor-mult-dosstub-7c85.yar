rule TTP_XOR_MULT_DOSStub_7c85 {
  strings:
    $key_7c85 = { 28 ed [2] 5c f5 [2] 1b f7 [2] 5c e6 [2] 12 ea [2] 1e e0 [2] 09 eb [2] 12 a5 [2] 2f }

  condition:
    any of them
}