rule TTP_XOR_MULT_DOSStub_7ace {
  strings:
    $key_7ace = { 2e a6 [2] 5a be [2] 1d bc [2] 5a ad [2] 14 a1 [2] 18 ab [2] 0f a0 [2] 14 ee [2] 29 }

  condition:
    any of them
}