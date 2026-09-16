rule TTP_XOR_MULT_DOSStub_1bd6 {
  strings:
    $key_1bd6 = { 4f be [2] 3b a6 [2] 7c a4 [2] 3b b5 [2] 75 b9 [2] 79 b3 [2] 6e b8 [2] 75 f6 [2] 48 }

  condition:
    any of them
}