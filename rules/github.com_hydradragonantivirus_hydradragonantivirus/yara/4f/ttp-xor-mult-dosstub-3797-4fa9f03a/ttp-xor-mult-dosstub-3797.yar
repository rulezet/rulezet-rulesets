rule TTP_XOR_MULT_DOSStub_3797 {
  strings:
    $key_3797 = { 63 ff [2] 17 e7 [2] 50 e5 [2] 17 f4 [2] 59 f8 [2] 55 f2 [2] 42 f9 [2] 59 b7 [2] 64 }

  condition:
    any of them
}