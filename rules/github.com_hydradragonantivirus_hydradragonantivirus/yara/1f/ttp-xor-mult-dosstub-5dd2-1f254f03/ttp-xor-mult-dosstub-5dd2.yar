rule TTP_XOR_MULT_DOSStub_5dd2 {
  strings:
    $key_5dd2 = { 09 ba [2] 7d a2 [2] 3a a0 [2] 7d b1 [2] 33 bd [2] 3f b7 [2] 28 bc [2] 33 f2 [2] 0e }

  condition:
    any of them
}