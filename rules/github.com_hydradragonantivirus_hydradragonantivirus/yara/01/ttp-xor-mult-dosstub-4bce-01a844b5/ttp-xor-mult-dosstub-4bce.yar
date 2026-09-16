rule TTP_XOR_MULT_DOSStub_4bce {
  strings:
    $key_4bce = { 1f a6 [2] 6b be [2] 2c bc [2] 6b ad [2] 25 a1 [2] 29 ab [2] 3e a0 [2] 25 ee [2] 18 }

  condition:
    any of them
}