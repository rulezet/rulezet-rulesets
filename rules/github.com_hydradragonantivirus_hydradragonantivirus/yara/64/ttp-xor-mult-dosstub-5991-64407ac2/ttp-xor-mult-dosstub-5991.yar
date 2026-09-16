rule TTP_XOR_MULT_DOSStub_5991 {
  strings:
    $key_5991 = { 0d f9 [2] 79 e1 [2] 3e e3 [2] 79 f2 [2] 37 fe [2] 3b f4 [2] 2c ff [2] 37 b1 [2] 0a }

  condition:
    any of them
}