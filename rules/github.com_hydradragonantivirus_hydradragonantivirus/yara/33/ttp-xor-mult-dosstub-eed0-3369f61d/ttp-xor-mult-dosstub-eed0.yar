rule TTP_XOR_MULT_DOSStub_eed0 {
  strings:
    $key_eed0 = { ba b8 [2] ce a0 [2] 89 a2 [2] ce b3 [2] 80 bf [2] 8c b5 [2] 9b be [2] 80 f0 [2] bd }

  condition:
    any of them
}