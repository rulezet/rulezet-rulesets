rule TTP_XOR_MULT_DOSStub_07c7 {
  strings:
    $key_07c7 = { 53 af [2] 27 b7 [2] 60 b5 [2] 27 a4 [2] 69 a8 [2] 65 a2 [2] 72 a9 [2] 69 e7 [2] 54 }

  condition:
    any of them
}