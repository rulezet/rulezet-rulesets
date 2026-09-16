rule TTP_XOR_MULT_DOSStub_0797 {
  strings:
    $key_0797 = { 53 ff [2] 27 e7 [2] 60 e5 [2] 27 f4 [2] 69 f8 [2] 65 f2 [2] 72 f9 [2] 69 b7 [2] 54 }

  condition:
    any of them
}