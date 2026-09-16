rule TTP_XOR_MULT_DOSStub_7bce {
  strings:
    $key_7bce = { 2f a6 [2] 5b be [2] 1c bc [2] 5b ad [2] 15 a1 [2] 19 ab [2] 0e a0 [2] 15 ee [2] 28 }

  condition:
    any of them
}