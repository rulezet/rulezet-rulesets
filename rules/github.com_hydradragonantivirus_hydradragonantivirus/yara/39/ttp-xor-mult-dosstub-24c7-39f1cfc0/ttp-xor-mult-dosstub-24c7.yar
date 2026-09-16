rule TTP_XOR_MULT_DOSStub_24c7 {
  strings:
    $key_24c7 = { 70 af [2] 04 b7 [2] 43 b5 [2] 04 a4 [2] 4a a8 [2] 46 a2 [2] 51 a9 [2] 4a e7 [2] 77 }

  condition:
    any of them
}