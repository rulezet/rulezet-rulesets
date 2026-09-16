rule TTP_XOR_MULT_DOSStub_4797 {
  strings:
    $key_4797 = { 13 ff [2] 67 e7 [2] 20 e5 [2] 67 f4 [2] 29 f8 [2] 25 f2 [2] 32 f9 [2] 29 b7 [2] 14 }

  condition:
    any of them
}