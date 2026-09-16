rule TTP_XOR_MULT_DOSStub_7491 {
  strings:
    $key_7491 = { 20 f9 [2] 54 e1 [2] 13 e3 [2] 54 f2 [2] 1a fe [2] 16 f4 [2] 01 ff [2] 1a b1 [2] 27 }

  condition:
    any of them
}