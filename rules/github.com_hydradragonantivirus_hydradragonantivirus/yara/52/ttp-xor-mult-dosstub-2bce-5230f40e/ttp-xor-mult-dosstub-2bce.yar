rule TTP_XOR_MULT_DOSStub_2bce {
  strings:
    $key_2bce = { 7f a6 [2] 0b be [2] 4c bc [2] 0b ad [2] 45 a1 [2] 49 ab [2] 5e a0 [2] 45 ee [2] 78 }

  condition:
    any of them
}