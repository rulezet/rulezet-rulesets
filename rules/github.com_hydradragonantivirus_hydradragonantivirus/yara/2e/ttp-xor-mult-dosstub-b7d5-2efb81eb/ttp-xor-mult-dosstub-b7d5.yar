rule TTP_XOR_MULT_DOSStub_b7d5 {
  strings:
    $key_b7d5 = { e3 bd [2] 97 a5 [2] d0 a7 [2] 97 b6 [2] d9 ba [2] d5 b0 [2] c2 bb [2] d9 f5 [2] e4 }

  condition:
    any of them
}