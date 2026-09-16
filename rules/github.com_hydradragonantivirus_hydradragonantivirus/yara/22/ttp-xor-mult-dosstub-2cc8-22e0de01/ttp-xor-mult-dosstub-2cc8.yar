rule TTP_XOR_MULT_DOSStub_2cc8 {
  strings:
    $key_2cc8 = { 78 a0 [2] 0c b8 [2] 4b ba [2] 0c ab [2] 42 a7 [2] 4e ad [2] 59 a6 [2] 42 e8 [2] 7f }

  condition:
    any of them
}