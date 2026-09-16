rule TTP_XOR_MULT_DOSStub_0991 {
  strings:
    $key_0991 = { 5d f9 [2] 29 e1 [2] 6e e3 [2] 29 f2 [2] 67 fe [2] 6b f4 [2] 7c ff [2] 67 b1 [2] 5a }

  condition:
    any of them
}