rule TTP_XOR_MULT_DOSStub_5086 {
  strings:
    $key_5086 = { 04 ee [2] 70 f6 [2] 37 f4 [2] 70 e5 [2] 3e e9 [2] 32 e3 [2] 25 e8 [2] 3e a6 [2] 03 }

  condition:
    any of them
}