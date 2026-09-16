rule TTP_XOR_MULT_DOSStub_3ed5 {
  strings:
    $key_3ed5 = { 6a bd [2] 1e a5 [2] 59 a7 [2] 1e b6 [2] 50 ba [2] 5c b0 [2] 4b bb [2] 50 f5 [2] 6d }

  condition:
    any of them
}