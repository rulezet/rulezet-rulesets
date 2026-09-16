rule TTP_XOR_MULT_DOSStub_6bd7 {
  strings:
    $key_6bd7 = { 3f bf [2] 4b a7 [2] 0c a5 [2] 4b b4 [2] 05 b8 [2] 09 b2 [2] 1e b9 [2] 05 f7 [2] 38 }

  condition:
    any of them
}