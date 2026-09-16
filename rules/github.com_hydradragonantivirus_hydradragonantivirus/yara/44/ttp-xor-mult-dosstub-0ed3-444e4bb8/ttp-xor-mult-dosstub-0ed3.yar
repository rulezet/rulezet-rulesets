rule TTP_XOR_MULT_DOSStub_0ed3 {
  strings:
    $key_0ed3 = { 5a bb [2] 2e a3 [2] 69 a1 [2] 2e b0 [2] 60 bc [2] 6c b6 [2] 7b bd [2] 60 f3 [2] 5d }

  condition:
    any of them
}