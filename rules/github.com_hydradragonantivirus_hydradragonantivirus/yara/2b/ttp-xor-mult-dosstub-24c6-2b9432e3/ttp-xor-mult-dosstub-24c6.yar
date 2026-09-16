rule TTP_XOR_MULT_DOSStub_24c6 {
  strings:
    $key_24c6 = { 70 ae [2] 04 b6 [2] 43 b4 [2] 04 a5 [2] 4a a9 [2] 46 a3 [2] 51 a8 [2] 4a e6 [2] 77 }

  condition:
    any of them
}