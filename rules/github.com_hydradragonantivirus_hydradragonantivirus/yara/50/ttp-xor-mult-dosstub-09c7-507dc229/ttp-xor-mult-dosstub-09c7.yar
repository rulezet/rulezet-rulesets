rule TTP_XOR_MULT_DOSStub_09c7 {
  strings:
    $key_09c7 = { 5d af [2] 29 b7 [2] 6e b5 [2] 29 a4 [2] 67 a8 [2] 6b a2 [2] 7c a9 [2] 67 e7 [2] 5a }

  condition:
    any of them
}