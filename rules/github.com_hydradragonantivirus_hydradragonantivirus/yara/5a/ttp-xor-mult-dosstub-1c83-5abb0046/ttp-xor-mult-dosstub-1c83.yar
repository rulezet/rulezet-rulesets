rule TTP_XOR_MULT_DOSStub_1c83 {
  strings:
    $key_1c83 = { 48 eb [2] 3c f3 [2] 7b f1 [2] 3c e0 [2] 72 ec [2] 7e e6 [2] 69 ed [2] 72 a3 [2] 4f }

  condition:
    any of them
}