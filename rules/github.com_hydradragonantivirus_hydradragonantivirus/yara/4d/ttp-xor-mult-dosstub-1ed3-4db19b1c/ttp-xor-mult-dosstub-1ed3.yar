rule TTP_XOR_MULT_DOSStub_1ed3 {
  strings:
    $key_1ed3 = { 4a bb [2] 3e a3 [2] 79 a1 [2] 3e b0 [2] 70 bc [2] 7c b6 [2] 6b bd [2] 70 f3 [2] 4d }

  condition:
    any of them
}