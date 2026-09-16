rule TTP_XOR_MULT_DOSStub_fed5 {
  strings:
    $key_fed5 = { aa bd [2] de a5 [2] 99 a7 [2] de b6 [2] 90 ba [2] 9c b0 [2] 8b bb [2] 90 f5 [2] ad }

  condition:
    any of them
}