rule TTP_XOR_MULT_DOSStub_5cce {
  strings:
    $key_5cce = { 08 a6 [2] 7c be [2] 3b bc [2] 7c ad [2] 32 a1 [2] 3e ab [2] 29 a0 [2] 32 ee [2] 0f }

  condition:
    any of them
}