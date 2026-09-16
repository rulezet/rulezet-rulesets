rule TTP_XOR_MULT_DOSStub_0ec7 {
  strings:
    $key_0ec7 = { 5a af [2] 2e b7 [2] 69 b5 [2] 2e a4 [2] 60 a8 [2] 6c a2 [2] 7b a9 [2] 60 e7 [2] 5d }

  condition:
    any of them
}