rule TTP_XOR_MULT_DOSStub_fed2 {
  strings:
    $key_fed2 = { aa ba [2] de a2 [2] 99 a0 [2] de b1 [2] 90 bd [2] 9c b7 [2] 8b bc [2] 90 f2 [2] ad }

  condition:
    any of them
}