rule TTP_XOR_MULT_DOSStub_0fd3 {
  strings:
    $key_0fd3 = { 5b bb [2] 2f a3 [2] 68 a1 [2] 2f b0 [2] 61 bc [2] 6d b6 [2] 7a bd [2] 61 f3 [2] 5c }

  condition:
    any of them
}