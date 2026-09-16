rule TTP_XOR_MULT_DOSStub_7686 {
  strings:
    $key_7686 = { 22 ee [2] 56 f6 [2] 11 f4 [2] 56 e5 [2] 18 e9 [2] 14 e3 [2] 03 e8 [2] 18 a6 [2] 25 }

  condition:
    any of them
}