rule TTP_XOR_MULT_DOSStub_5697 {
  strings:
    $key_5697 = { 02 ff [2] 76 e7 [2] 31 e5 [2] 76 f4 [2] 38 f8 [2] 34 f2 [2] 23 f9 [2] 38 b7 [2] 05 }

  condition:
    any of them
}