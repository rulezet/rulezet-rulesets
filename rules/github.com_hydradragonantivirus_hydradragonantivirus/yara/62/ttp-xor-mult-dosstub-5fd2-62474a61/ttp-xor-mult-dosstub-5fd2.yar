rule TTP_XOR_MULT_DOSStub_5fd2 {
  strings:
    $key_5fd2 = { 0b ba [2] 7f a2 [2] 38 a0 [2] 7f b1 [2] 31 bd [2] 3d b7 [2] 2a bc [2] 31 f2 [2] 0c }

  condition:
    any of them
}