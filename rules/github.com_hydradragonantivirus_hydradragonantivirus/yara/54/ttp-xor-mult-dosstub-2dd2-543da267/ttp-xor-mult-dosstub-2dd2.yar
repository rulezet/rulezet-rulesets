rule TTP_XOR_MULT_DOSStub_2dd2 {
  strings:
    $key_2dd2 = { 79 ba [2] 0d a2 [2] 4a a0 [2] 0d b1 [2] 43 bd [2] 4f b7 [2] 58 bc [2] 43 f2 [2] 7e }

  condition:
    any of them
}