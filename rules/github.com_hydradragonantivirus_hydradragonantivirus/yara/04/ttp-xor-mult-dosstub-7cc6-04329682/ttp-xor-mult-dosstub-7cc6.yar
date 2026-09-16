rule TTP_XOR_MULT_DOSStub_7cc6 {
  strings:
    $key_7cc6 = { 28 ae [2] 5c b6 [2] 1b b4 [2] 5c a5 [2] 12 a9 [2] 1e a3 [2] 09 a8 [2] 12 e6 [2] 2f }

  condition:
    any of them
}