rule TTP_XOR_MULT_DOSStub_3c85 {
  strings:
    $key_3c85 = { 68 ed [2] 1c f5 [2] 5b f7 [2] 1c e6 [2] 52 ea [2] 5e e0 [2] 49 eb [2] 52 a5 [2] 6f }

  condition:
    any of them
}