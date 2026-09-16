rule TTP_XOR_MULT_DOSStub_12c7 {
  strings:
    $key_12c7 = { 46 af [2] 32 b7 [2] 75 b5 [2] 32 a4 [2] 7c a8 [2] 70 a2 [2] 67 a9 [2] 7c e7 [2] 41 }

  condition:
    any of them
}