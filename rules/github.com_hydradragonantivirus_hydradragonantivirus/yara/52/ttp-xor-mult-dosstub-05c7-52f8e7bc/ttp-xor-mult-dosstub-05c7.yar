rule TTP_XOR_MULT_DOSStub_05c7 {
  strings:
    $key_05c7 = { 51 af [2] 25 b7 [2] 62 b5 [2] 25 a4 [2] 6b a8 [2] 67 a2 [2] 70 a9 [2] 6b e7 [2] 56 }

  condition:
    any of them
}