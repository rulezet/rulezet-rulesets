rule TTP_XOR_MULT_DOSStub_3990 {
  strings:
    $key_3990 = { 6d f8 [2] 19 e0 [2] 5e e2 [2] 19 f3 [2] 57 ff [2] 5b f5 [2] 4c fe [2] 57 b0 [2] 6a }

  condition:
    any of them
}