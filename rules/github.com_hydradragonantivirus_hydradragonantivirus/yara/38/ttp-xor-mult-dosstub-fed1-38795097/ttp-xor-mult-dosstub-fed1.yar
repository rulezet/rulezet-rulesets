rule TTP_XOR_MULT_DOSStub_fed1 {
  strings:
    $key_fed1 = { aa b9 [2] de a1 [2] 99 a3 [2] de b2 [2] 90 be [2] 9c b4 [2] 8b bf [2] 90 f1 [2] ad }

  condition:
    any of them
}