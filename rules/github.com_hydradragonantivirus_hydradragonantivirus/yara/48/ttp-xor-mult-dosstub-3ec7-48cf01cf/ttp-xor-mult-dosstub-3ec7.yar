rule TTP_XOR_MULT_DOSStub_3ec7 {
  strings:
    $key_3ec7 = { 6a af [2] 1e b7 [2] 59 b5 [2] 1e a4 [2] 50 a8 [2] 5c a2 [2] 4b a9 [2] 50 e7 [2] 6d }

  condition:
    any of them
}