rule TTP_XOR_MULT_DOSStub_2386 {
  strings:
    $key_2386 = { 77 ee [2] 03 f6 [2] 44 f4 [2] 03 e5 [2] 4d e9 [2] 41 e3 [2] 56 e8 [2] 4d a6 [2] 70 }

  condition:
    any of them
}