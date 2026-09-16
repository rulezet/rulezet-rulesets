rule TTP_XOR_MULT_DOSStub_3fd1 {
  strings:
    $key_3fd1 = { 6b b9 [2] 1f a1 [2] 58 a3 [2] 1f b2 [2] 51 be [2] 5d b4 [2] 4a bf [2] 51 f1 [2] 6c }

  condition:
    any of them
}