rule TTP_XOR_MULT_DOSStub_0cce {
  strings:
    $key_0cce = { 58 a6 [2] 2c be [2] 6b bc [2] 2c ad [2] 62 a1 [2] 6e ab [2] 79 a0 [2] 62 ee [2] 5f }

  condition:
    any of them
}