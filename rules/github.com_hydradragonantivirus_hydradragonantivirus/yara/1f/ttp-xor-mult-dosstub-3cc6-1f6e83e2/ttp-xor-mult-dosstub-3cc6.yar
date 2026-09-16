rule TTP_XOR_MULT_DOSStub_3cc6 {
  strings:
    $key_3cc6 = { 68 ae [2] 1c b6 [2] 5b b4 [2] 1c a5 [2] 52 a9 [2] 5e a3 [2] 49 a8 [2] 52 e6 [2] 6f }

  condition:
    any of them
}