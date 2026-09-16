rule TTP_XOR_MULT_DOSStub_1cce {
  strings:
    $key_1cce = { 48 a6 [2] 3c be [2] 7b bc [2] 3c ad [2] 72 a1 [2] 7e ab [2] 69 a0 [2] 72 ee [2] 4f }

  condition:
    any of them
}