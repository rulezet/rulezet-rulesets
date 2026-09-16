rule TTP_XOR_MULT_DOSStub_3486 {
  strings:
    $key_3486 = { 60 ee [2] 14 f6 [2] 53 f4 [2] 14 e5 [2] 5a e9 [2] 56 e3 [2] 41 e8 [2] 5a a6 [2] 67 }

  condition:
    any of them
}