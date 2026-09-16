rule TTP_XOR_MULT_DOSStub_5c85 {
  strings:
    $key_5c85 = { 08 ed [2] 7c f5 [2] 3b f7 [2] 7c e6 [2] 32 ea [2] 3e e0 [2] 29 eb [2] 32 a5 [2] 0f }

  condition:
    any of them
}