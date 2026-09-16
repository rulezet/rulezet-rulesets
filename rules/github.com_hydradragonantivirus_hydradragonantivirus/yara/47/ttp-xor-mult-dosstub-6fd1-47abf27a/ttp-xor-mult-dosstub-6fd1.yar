rule TTP_XOR_MULT_DOSStub_6fd1 {
  strings:
    $key_6fd1 = { 3b b9 [2] 4f a1 [2] 08 a3 [2] 4f b2 [2] 01 be [2] 0d b4 [2] 1a bf [2] 01 f1 [2] 3c }

  condition:
    any of them
}