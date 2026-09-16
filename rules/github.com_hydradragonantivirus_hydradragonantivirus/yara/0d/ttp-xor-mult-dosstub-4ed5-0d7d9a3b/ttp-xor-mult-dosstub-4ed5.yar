rule TTP_XOR_MULT_DOSStub_4ed5 {
  strings:
    $key_4ed5 = { 1a bd [2] 6e a5 [2] 29 a7 [2] 6e b6 [2] 20 ba [2] 2c b0 [2] 3b bb [2] 20 f5 [2] 1d }

  condition:
    any of them
}