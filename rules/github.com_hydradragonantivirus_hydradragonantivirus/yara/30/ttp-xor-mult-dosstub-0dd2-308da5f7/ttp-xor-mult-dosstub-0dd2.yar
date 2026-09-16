rule TTP_XOR_MULT_DOSStub_0dd2 {
  strings:
    $key_0dd2 = { 59 ba [2] 2d a2 [2] 6a a0 [2] 2d b1 [2] 63 bd [2] 6f b7 [2] 78 bc [2] 63 f2 [2] 5e }

  condition:
    any of them
}