rule TTP_XOR_MULT_DOSStub_2697 {
  strings:
    $key_2697 = { 72 ff [2] 06 e7 [2] 41 e5 [2] 06 f4 [2] 48 f8 [2] 44 f2 [2] 53 f9 [2] 48 b7 [2] 75 }

  condition:
    any of them
}