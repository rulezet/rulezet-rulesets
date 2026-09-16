rule TTP_XOR_MULT_DOSStub_bbd3 {
  strings:
    $key_bbd3 = { ef bb [2] 9b a3 [2] dc a1 [2] 9b b0 [2] d5 bc [2] d9 b6 [2] ce bd [2] d5 f3 [2] e8 }

  condition:
    any of them
}