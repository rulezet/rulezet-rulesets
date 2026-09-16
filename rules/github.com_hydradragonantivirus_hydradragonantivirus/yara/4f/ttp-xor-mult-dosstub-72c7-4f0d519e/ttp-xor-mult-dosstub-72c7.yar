rule TTP_XOR_MULT_DOSStub_72c7 {
  strings:
    $key_72c7 = { 26 af [2] 52 b7 [2] 15 b5 [2] 52 a4 [2] 1c a8 [2] 10 a2 [2] 07 a9 [2] 1c e7 [2] 21 }

  condition:
    any of them
}