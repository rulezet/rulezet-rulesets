rule TTP_XOR_MULT_DOSStub_0990 {
  strings:
    $key_0990 = { 5d f8 [2] 29 e0 [2] 6e e2 [2] 29 f3 [2] 67 ff [2] 6b f5 [2] 7c fe [2] 67 b0 [2] 5a }

  condition:
    any of them
}