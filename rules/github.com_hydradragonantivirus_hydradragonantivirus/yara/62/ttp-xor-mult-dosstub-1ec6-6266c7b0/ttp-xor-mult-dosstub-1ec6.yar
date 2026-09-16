rule TTP_XOR_MULT_DOSStub_1ec6 {
  strings:
    $key_1ec6 = { 4a ae [2] 3e b6 [2] 79 b4 [2] 3e a5 [2] 70 a9 [2] 7c a3 [2] 6b a8 [2] 70 e6 [2] 4d }

  condition:
    any of them
}