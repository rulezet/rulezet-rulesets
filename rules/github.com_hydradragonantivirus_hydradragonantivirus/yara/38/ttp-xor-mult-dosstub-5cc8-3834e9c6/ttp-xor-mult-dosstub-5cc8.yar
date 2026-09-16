rule TTP_XOR_MULT_DOSStub_5cc8 {
  strings:
    $key_5cc8 = { 08 a0 [2] 7c b8 [2] 3b ba [2] 7c ab [2] 32 a7 [2] 3e ad [2] 29 a6 [2] 32 e8 [2] 0f }

  condition:
    any of them
}