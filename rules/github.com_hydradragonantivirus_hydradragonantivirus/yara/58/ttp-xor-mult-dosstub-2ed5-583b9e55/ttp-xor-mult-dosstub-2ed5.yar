rule TTP_XOR_MULT_DOSStub_2ed5 {
  strings:
    $key_2ed5 = { 7a bd [2] 0e a5 [2] 49 a7 [2] 0e b6 [2] 40 ba [2] 4c b0 [2] 5b bb [2] 40 f5 [2] 7d }

  condition:
    any of them
}