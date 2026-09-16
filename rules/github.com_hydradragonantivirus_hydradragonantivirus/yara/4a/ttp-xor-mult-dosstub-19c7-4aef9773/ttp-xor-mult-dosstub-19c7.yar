rule TTP_XOR_MULT_DOSStub_19c7 {
  strings:
    $key_19c7 = { 4d af [2] 39 b7 [2] 7e b5 [2] 39 a4 [2] 77 a8 [2] 7b a2 [2] 6c a9 [2] 77 e7 [2] 4a }

  condition:
    any of them
}