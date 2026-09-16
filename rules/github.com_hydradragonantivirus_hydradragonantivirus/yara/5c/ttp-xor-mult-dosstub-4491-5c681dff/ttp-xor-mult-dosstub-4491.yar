rule TTP_XOR_MULT_DOSStub_4491 {
  strings:
    $key_4491 = { 10 f9 [2] 64 e1 [2] 23 e3 [2] 64 f2 [2] 2a fe [2] 26 f4 [2] 31 ff [2] 2a b1 [2] 17 }

  condition:
    any of them
}