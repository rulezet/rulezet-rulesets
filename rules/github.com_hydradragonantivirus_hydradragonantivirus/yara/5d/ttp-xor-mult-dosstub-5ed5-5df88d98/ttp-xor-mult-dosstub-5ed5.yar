rule TTP_XOR_MULT_DOSStub_5ed5 {
  strings:
    $key_5ed5 = { 0a bd [2] 7e a5 [2] 39 a7 [2] 7e b6 [2] 30 ba [2] 3c b0 [2] 2b bb [2] 30 f5 [2] 0d }

  condition:
    any of them
}