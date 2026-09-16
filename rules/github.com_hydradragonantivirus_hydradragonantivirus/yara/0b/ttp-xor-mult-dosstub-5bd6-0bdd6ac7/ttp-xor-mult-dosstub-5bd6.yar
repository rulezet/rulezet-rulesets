rule TTP_XOR_MULT_DOSStub_5bd6 {
  strings:
    $key_5bd6 = { 0f be [2] 7b a6 [2] 3c a4 [2] 7b b5 [2] 35 b9 [2] 39 b3 [2] 2e b8 [2] 35 f6 [2] 08 }

  condition:
    any of them
}