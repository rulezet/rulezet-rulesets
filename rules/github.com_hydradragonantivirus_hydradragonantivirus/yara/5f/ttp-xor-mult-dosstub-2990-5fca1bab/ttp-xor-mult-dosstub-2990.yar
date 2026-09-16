rule TTP_XOR_MULT_DOSStub_2990 {
  strings:
    $key_2990 = { 7d f8 [2] 09 e0 [2] 4e e2 [2] 09 f3 [2] 47 ff [2] 4b f5 [2] 5c fe [2] 47 b0 [2] 7a }

  condition:
    any of them
}