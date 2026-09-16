rule TTP_XOR_MULT_DOSStub_eed4 {
  strings:
    $key_eed4 = { ba bc [2] ce a4 [2] 89 a6 [2] ce b7 [2] 80 bb [2] 8c b1 [2] 9b ba [2] 80 f4 [2] bd }

  condition:
    any of them
}