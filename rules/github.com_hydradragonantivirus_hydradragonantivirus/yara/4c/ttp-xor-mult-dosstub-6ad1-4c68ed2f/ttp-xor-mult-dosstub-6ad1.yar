rule TTP_XOR_MULT_DOSStub_6ad1 {
  strings:
    $key_6ad1 = { 3e b9 [2] 4a a1 [2] 0d a3 [2] 4a b2 [2] 04 be [2] 08 b4 [2] 1f bf [2] 04 f1 [2] 39 }

  condition:
    any of them
}