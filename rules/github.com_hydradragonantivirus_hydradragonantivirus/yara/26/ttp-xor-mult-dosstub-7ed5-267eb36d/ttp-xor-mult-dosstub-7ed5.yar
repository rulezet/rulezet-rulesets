rule TTP_XOR_MULT_DOSStub_7ed5 {
  strings:
    $key_7ed5 = { 2a bd [2] 5e a5 [2] 19 a7 [2] 5e b6 [2] 10 ba [2] 1c b0 [2] 0b bb [2] 10 f5 [2] 2d }

  condition:
    any of them
}