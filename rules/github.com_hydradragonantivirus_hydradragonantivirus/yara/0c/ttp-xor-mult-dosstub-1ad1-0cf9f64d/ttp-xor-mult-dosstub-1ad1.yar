rule TTP_XOR_MULT_DOSStub_1ad1 {
  strings:
    $key_1ad1 = { 4e b9 [2] 3a a1 [2] 7d a3 [2] 3a b2 [2] 74 be [2] 78 b4 [2] 6f bf [2] 74 f1 [2] 49 }

  condition:
    any of them
}