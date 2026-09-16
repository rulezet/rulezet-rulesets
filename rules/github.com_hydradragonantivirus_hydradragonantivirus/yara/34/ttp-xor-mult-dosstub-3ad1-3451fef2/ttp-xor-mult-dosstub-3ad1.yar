rule TTP_XOR_MULT_DOSStub_3ad1 {
  strings:
    $key_3ad1 = { 6e b9 [2] 1a a1 [2] 5d a3 [2] 1a b2 [2] 54 be [2] 58 b4 [2] 4f bf [2] 54 f1 [2] 69 }

  condition:
    any of them
}