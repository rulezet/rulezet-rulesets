rule TTP_XOR_MULT_DOSStub_eed5 {
  strings:
    $key_eed5 = { ba bd [2] ce a5 [2] 89 a7 [2] ce b6 [2] 80 ba [2] 8c b0 [2] 9b bb [2] 80 f5 [2] bd }

  condition:
    any of them
}