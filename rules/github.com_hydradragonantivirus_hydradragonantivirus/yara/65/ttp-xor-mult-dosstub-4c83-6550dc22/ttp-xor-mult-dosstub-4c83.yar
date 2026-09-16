rule TTP_XOR_MULT_DOSStub_4c83 {
  strings:
    $key_4c83 = { 18 eb [2] 6c f3 [2] 2b f1 [2] 6c e0 [2] 22 ec [2] 2e e6 [2] 39 ed [2] 22 a3 [2] 1f }

  condition:
    any of them
}