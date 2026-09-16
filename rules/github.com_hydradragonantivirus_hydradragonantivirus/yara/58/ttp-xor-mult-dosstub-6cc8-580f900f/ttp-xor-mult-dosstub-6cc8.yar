rule TTP_XOR_MULT_DOSStub_6cc8 {
  strings:
    $key_6cc8 = { 38 a0 [2] 4c b8 [2] 0b ba [2] 4c ab [2] 02 a7 [2] 0e ad [2] 19 a6 [2] 02 e8 [2] 3f }

  condition:
    any of them
}