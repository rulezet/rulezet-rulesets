rule TTP_XOR_MULT_DOSStub_4283 {
  strings:
    $key_4283 = { 16 eb [2] 62 f3 [2] 25 f1 [2] 62 e0 [2] 2c ec [2] 20 e6 [2] 37 ed [2] 2c a3 [2] 11 }

  condition:
    any of them
}