rule TTP_XOR_MULT_DOSStub_3697 {
  strings:
    $key_3697 = { 62 ff [2] 16 e7 [2] 51 e5 [2] 16 f4 [2] 58 f8 [2] 54 f2 [2] 43 f9 [2] 58 b7 [2] 65 }

  condition:
    any of them
}