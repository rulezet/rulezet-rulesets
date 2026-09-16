rule TTP_XOR_MULT_DOSStub_09d5 {
  strings:
    $key_09d5 = { 5d bd [2] 29 a5 [2] 6e a7 [2] 29 b6 [2] 67 ba [2] 6b b0 [2] 7c bb [2] 67 f5 [2] 5a }

  condition:
    any of them
}