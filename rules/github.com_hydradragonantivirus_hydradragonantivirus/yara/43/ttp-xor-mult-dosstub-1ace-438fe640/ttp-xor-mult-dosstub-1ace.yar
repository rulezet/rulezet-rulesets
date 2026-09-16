rule TTP_XOR_MULT_DOSStub_1ace {
  strings:
    $key_1ace = { 4e a6 [2] 3a be [2] 7d bc [2] 3a ad [2] 74 a1 [2] 78 ab [2] 6f a0 [2] 74 ee [2] 49 }

  condition:
    any of them
}