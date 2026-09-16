rule TTP_XOR_MULT_DOSStub_1283 {
  strings:
    $key_1283 = { 46 eb [2] 32 f3 [2] 75 f1 [2] 32 e0 [2] 7c ec [2] 70 e6 [2] 67 ed [2] 7c a3 [2] 41 }

  condition:
    any of them
}