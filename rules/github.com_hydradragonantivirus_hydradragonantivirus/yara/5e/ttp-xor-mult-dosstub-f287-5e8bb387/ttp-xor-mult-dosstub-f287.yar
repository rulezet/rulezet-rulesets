rule TTP_XOR_MULT_DOSStub_f287 {
  strings:
    $key_f287 = { a6 ef [2] d2 f7 [2] 95 f5 [2] d2 e4 [2] 9c e8 [2] 90 e2 [2] 87 e9 [2] 9c a7 [2] a1 }

  condition:
    any of them
}