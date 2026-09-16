rule TTP_XOR_MULT_DOSStub_0ad1 {
  strings:
    $key_0ad1 = { 5e b9 [2] 2a a1 [2] 6d a3 [2] 2a b2 [2] 64 be [2] 68 b4 [2] 7f bf [2] 64 f1 [2] 59 }

  condition:
    any of them
}