rule TTP_XOR_MULT_DOSStub_30c7 {
  strings:
    $key_30c7 = { 64 af [2] 10 b7 [2] 57 b5 [2] 10 a4 [2] 5e a8 [2] 52 a2 [2] 45 a9 [2] 5e e7 [2] 63 }

  condition:
    any of them
}