rule TTP_XOR_MULT_DOSStub_2cc0 {
  strings:
    $key_2cc0 = { 78 a8 [2] 0c b0 [2] 4b b2 [2] 0c a3 [2] 42 af [2] 4e a5 [2] 59 ae [2] 42 e0 [2] 7f }

  condition:
    any of them
}