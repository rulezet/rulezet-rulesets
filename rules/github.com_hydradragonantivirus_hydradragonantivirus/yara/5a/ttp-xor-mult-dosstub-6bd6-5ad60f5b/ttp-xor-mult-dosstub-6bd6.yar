rule TTP_XOR_MULT_DOSStub_6bd6 {
  strings:
    $key_6bd6 = { 3f be [2] 4b a6 [2] 0c a4 [2] 4b b5 [2] 05 b9 [2] 09 b3 [2] 1e b8 [2] 05 f6 [2] 38 }

  condition:
    any of them
}