rule TTP_XOR_MULT_DOSStub_eed6 {
  strings:
    $key_eed6 = { ba be [2] ce a6 [2] 89 a4 [2] ce b5 [2] 80 b9 [2] 8c b3 [2] 9b b8 [2] 80 f6 [2] bd }

  condition:
    any of them
}