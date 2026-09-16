rule TTP_XOR_MULT_DOSStub_6fd2 {
  strings:
    $key_6fd2 = { 3b ba [2] 4f a2 [2] 08 a0 [2] 4f b1 [2] 01 bd [2] 0d b7 [2] 1a bc [2] 01 f2 [2] 3c }

  condition:
    any of them
}