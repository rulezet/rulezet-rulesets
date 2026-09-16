rule TTP_XOR_MULT_DOSStub_2486 {
  strings:
    $key_2486 = { 70 ee [2] 04 f6 [2] 43 f4 [2] 04 e5 [2] 4a e9 [2] 46 e3 [2] 51 e8 [2] 4a a6 [2] 77 }

  condition:
    any of them
}