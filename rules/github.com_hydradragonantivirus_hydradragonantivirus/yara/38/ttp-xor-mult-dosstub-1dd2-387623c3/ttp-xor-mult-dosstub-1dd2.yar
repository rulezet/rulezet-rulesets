rule TTP_XOR_MULT_DOSStub_1dd2 {
  strings:
    $key_1dd2 = { 49 ba [2] 3d a2 [2] 7a a0 [2] 3d b1 [2] 73 bd [2] 7f b7 [2] 68 bc [2] 73 f2 [2] 4e }

  condition:
    any of them
}