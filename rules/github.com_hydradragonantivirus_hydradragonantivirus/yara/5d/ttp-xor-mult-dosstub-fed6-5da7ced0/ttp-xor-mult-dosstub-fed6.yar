rule TTP_XOR_MULT_DOSStub_fed6 {
  strings:
    $key_fed6 = { aa be [2] de a6 [2] 99 a4 [2] de b5 [2] 90 b9 [2] 9c b3 [2] 8b b8 [2] 90 f6 [2] ad }

  condition:
    any of them
}