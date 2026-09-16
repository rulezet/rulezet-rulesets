rule TTP_XOR_MULT_DOSStub_34d6 {
  strings:
    $key_34d6 = { 60 be [2] 14 a6 [2] 53 a4 [2] 14 b5 [2] 5a b9 [2] 56 b3 [2] 41 b8 [2] 5a f6 [2] 67 }

  condition:
    any of them
}